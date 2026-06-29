package qurl_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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

	// ManifestDigest produces the value an application pins (a real, non-zero digest).
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

func TestRelayErrorString(t *testing.T) {
	tests := []struct {
		name string
		err  *qurl.RelayError
		want string
	}{
		{name: "nil", err: nil, want: "qurl: platform access error"},
		{name: "empty message", err: &qurl.RelayError{}, want: "qurl: platform access error"},
		{name: "adds prefix", err: &qurl.RelayError{Msg: "relay POST failed"}, want: "qurl: relay POST failed"},
		{name: "keeps prefix", err: &qurl.RelayError{Msg: "qurl: relay POST failed"}, want: "qurl: relay POST failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("RelayError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFragmentExportedFieldsMirrorCore guards wrapFragment, which hand-copies the
// exported fields of the internal fragment. If the core fragment gains an exported
// field, this parity check fails loudly rather than the public Fragment silently
// dropping it. (Claims and Secret fields are guarded at compile time in facade.go.)
func TestFragmentExportedFieldsMirrorCore(t *testing.T) {
	got := exportedFieldNames(reflect.TypeFor[qurl.Fragment]())
	want := exportedFieldNames(reflect.TypeFor[qv2.Fragment]())
	if !slices.Equal(got, want) {
		t.Errorf("qurl.Fragment exported fields %v != core %v — update wrapFragment in facade.go", got, want)
	}
}

func TestClaimsAndSecretJSONTagsMirrorCore(t *testing.T) {
	assertJSONTagsMirror(t, reflect.TypeFor[qurl.Claims](), reflect.TypeFor[qv2.Claims]())
	assertJSONTagsMirror(t, reflect.TypeFor[qurl.Secret](), reflect.TypeFor[qv2.Secret]())
}

func assertJSONTagsMirror(t *testing.T, got, want reflect.Type) {
	t.Helper()
	if got.NumField() != want.NumField() {
		t.Fatalf("%s field count = %d, want %d", got, got.NumField(), want.NumField())
	}
	for i := range got.NumField() {
		gotField := got.Field(i)
		wantField := want.Field(i)
		if gotField.Name != wantField.Name {
			t.Fatalf("%s field %d = %s, want %s", got, i, gotField.Name, wantField.Name)
		}
		if gotTag, wantTag := gotField.Tag.Get("json"), wantField.Tag.Get("json"); gotTag != wantTag {
			t.Fatalf("%s.%s json tag = %q, want %q", got, gotField.Name, gotTag, wantTag)
		}
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

func trustStoreFor(t *testing.T, signer *qurl.LocalSigner) *qurl.TrustStore {
	t.Helper()
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})
	if err != nil {
		t.Fatalf("NewTrustStoreFromDER: %v", err)
	}
	return trust
}

func exampleX25519Public(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return k.PublicKey().Bytes()
}

func exampleP256SPKI(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-256 SPKI: %v", err)
	}
	return der
}

// TestVerifyLinkSurfacesAllClaimFields mints a link with every CreateParams field set,
// verifies it, and asserts every public Claims field (plus Secret and the verbatim
// Fragment parts) survived the wrap copy. With the compile-time field-parity guards in
// facade.go this closes the hand-copy boundary: a wrap that forgets to populate a field
// fails here instead of silently returning a zero value.
func TestVerifyLinkSurfacesAllClaimFields(t *testing.T) {
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	const (
		relay = "https://relay.example.com"
		jti   = "qurl_facade_fields"
		cell  = "edge-cell-7"
	)
	var iat, nbf, exp int64 = 1_700_000_000, 1_700_000_001, 1_700_003_600

	link, err := qurl.CreatePortalWithParams(context.Background(), signer, qurl.CreateParams{
		CellPublicKey:     exampleX25519Public(t),
		RelayURL:          relay,
		ResourcePublicKey: exampleP256SPKI(t),
		CellID:            cell,
		JTI:               jti,
		IssuedAt:          iat,
		NotBefore:         nbf,
		Expiry:            exp,
	})
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}

	frag, err := qurl.VerifyLink(link, trustStoreFor(t, signer))
	if err != nil {
		t.Fatalf("VerifyLink: %v", err)
	}
	c := frag.Claims
	if c == nil {
		t.Fatal("Fragment.Claims is nil")
	}
	if c.V == 0 {
		t.Error("Claims.V not surfaced")
	}
	if c.Iss == "" {
		t.Error("Claims.Iss not surfaced")
	}
	if c.Kid != signer.KID() {
		t.Errorf("Claims.Kid = %q, want %q", c.Kid, signer.KID())
	}
	if c.Iat != iat {
		t.Errorf("Claims.Iat = %d, want %d", c.Iat, iat)
	}
	if c.Nbf != nbf {
		t.Errorf("Claims.Nbf = %d, want %d", c.Nbf, nbf)
	}
	if c.Exp != exp {
		t.Errorf("Claims.Exp = %d, want %d", c.Exp, exp)
	}
	if c.Jti != jti {
		t.Errorf("Claims.Jti = %q, want %q", c.Jti, jti)
	}
	if c.CellPublicKeyB64 == "" {
		t.Error("Claims.CellPublicKeyB64 not surfaced")
	}
	if c.CellID != cell {
		t.Errorf("Claims.CellID = %q, want %q", c.CellID, cell)
	}
	if c.RelayURL != relay {
		t.Errorf("Claims.RelayURL = %q, want %q", c.RelayURL, relay)
	}
	if c.ResourcePublicKeyB64 == "" {
		t.Error("Claims.ResourcePublicKeyB64 not surfaced")
	}
	if c.QurlUserPublicKeyB64 == "" {
		t.Error("Claims.QurlUserPublicKeyB64 not surfaced")
	}
	if frag.Secret == nil || frag.Secret.QurlUserPrivateKeyB64 == "" {
		t.Error("Fragment.Secret.QurlUserPrivateKeyB64 not surfaced")
	}
	if frag.ClaimsB64 == "" || frag.SecretB64 == "" || frag.SigB64 == "" {
		t.Error("Fragment verbatim base64url parts not surfaced")
	}
}
