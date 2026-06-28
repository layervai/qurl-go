package qurl_test

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/qurl"
)

// TestManifestFacadeRoundTrip exercises the re-exported discovery-manifest primitives
// end to end through the qurl front door — digest, sign, verify — so a publisher never
// has to reach past qurl. It also confirms the wrappers are wired to the right
// underlying functions (a mis-wired re-export would fail this round trip).
//
// (Error-sentinel identity across the façade boundary — that qurl.ErrSignature is the
// same value the core produces — is already exercised by Example_rejectsForgedLink.)
func TestManifestFacadeRoundTrip(t *testing.T) {
	signer, err := qurl.GenerateLocalSigner("manifest-key-2026")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	manifest := []byte(`{"profile":"qurl-trust","version":1}`)

	// ManifestDigest produces the value a deployment pins (a real, non-zero digest).
	if qurl.ManifestDigest(manifest) == ([32]byte{}) {
		t.Fatal("ManifestDigest returned the zero digest")
	}

	sig, err := qurl.SignManifest(context.Background(), signer, manifest)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	pub, err := qurl.ParseP256PublicKeyDER(pubDER)
	if err != nil {
		t.Fatalf("ParseP256PublicKeyDER: %v", err)
	}

	if err := qurl.VerifyManifestSignature(pub, manifest, sig); err != nil {
		t.Fatalf("a freshly signed manifest should verify: %v", err)
	}

	// Tampered manifest bytes must not verify under the same signature.
	if err := qurl.VerifyManifestSignature(pub, append(manifest, '!'), sig); err == nil {
		t.Fatal("tampered manifest unexpectedly verified")
	}
}

// TestFragmentExportedFieldsMirrorCore guards wrapFragment, which hand-copies the
// exported fields of the internal fragment. If the core fragment gains an exported
// field, this parity check fails loudly rather than the public Fragment silently
// dropping it. (Claims and Secret are guarded at compile time in facade.go.)
func TestFragmentExportedFieldsMirrorCore(t *testing.T) {
	got := exportedFieldNames(reflect.TypeFor[qurl.Fragment]())
	want := exportedFieldNames(reflect.TypeFor[qv2.Fragment]())
	if !slices.Equal(got, want) {
		t.Errorf("qurl.Fragment exported fields %v != core %v — update wrapFragment in facade.go", got, want)
	}
}

func exportedFieldNames(t reflect.Type) []string {
	var names []string
	for i := range t.NumField() {
		if f := t.Field(i); f.IsExported() {
			names = append(names, f.Name)
		}
	}
	return names
}
