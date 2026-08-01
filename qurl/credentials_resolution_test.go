package qurl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// OpenClient used to read ONLY the root-owned DefaultIssuerStatePath, which made
// the three-line issuing example untrue for anyone who simply holds an API key:
// before writing Go they had to become root and hand-author a JSON file. These
// pin the resolution order so that regression cannot return quietly.

func writeTokenFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"bearer_token":"tok-from-file"}`), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return path
}

func TestResolveCredentialsPrefersExplicitPath(t *testing.T) {
	dir := t.TempDir()
	explicit := writeTokenFile(t, dir, "explicit.json")
	t.Setenv(EnvAPIKey, "tok-from-env")

	got, err := resolveCredentials(explicit)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fp, ok := got.(fileCredentialProvider)
	if !ok || fp.path != explicit {
		t.Fatalf("explicit path did not win: %#v", got)
	}
}

func TestResolveCredentialsUsesAPIKeyEnv(t *testing.T) {
	t.Setenv(EnvAPIKey, "tok-from-env")
	t.Setenv(EnvAPIKeyFile, "")

	got, err := resolveCredentials("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := got.(bearerTokenCredential); !ok {
		t.Fatalf("QURL_API_KEY did not produce a bearer credential: %#v", got)
	}
}

// Whitespace-only is not a credential. Treating it as one would send an empty
// Authorization header and produce a confusing 401 instead of falling through.
func TestResolveCredentialsIgnoresBlankAPIKey(t *testing.T) {
	t.Setenv(EnvAPIKey, "   ")
	t.Setenv(EnvAPIKeyFile, "")

	got, err := resolveCredentials("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := got.(bearerTokenCredential); ok {
		t.Fatal("blank QURL_API_KEY was accepted as a credential")
	}
}

func TestResolveCredentialsUsesAPIKeyFileEnv(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "mounted.json")
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, path)

	got, err := resolveCredentials("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fp, ok := got.(fileCredentialProvider)
	if !ok || fp.path != path {
		t.Fatalf("QURL_API_KEY_FILE not honored: %#v", got)
	}
}

// A named file that does not exist must fail loudly. Falling through would
// silently authenticate as whatever the machine-wide credential happens to be —
// the wrong identity, discovered much later.
func TestResolveCredentialsRejectsMissingAPIKeyFile(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, filepath.Join(t.TempDir(), "absent.json"))

	if _, err := resolveCredentials(""); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("missing QURL_API_KEY_FILE: got %v, want ErrInvalidClientConfig", err)
	}
}

// QURL_API_KEY beats QURL_API_KEY_FILE: the inline value is the more specific
// statement of intent.
func TestResolveCredentialsAPIKeyBeatsAPIKeyFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvAPIKey, "tok-from-env")
	t.Setenv(EnvAPIKeyFile, writeTokenFile(t, dir, "mounted.json"))

	got, err := resolveCredentials("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := got.(bearerTokenCredential); !ok {
		t.Fatalf("QURL_API_KEY did not beat QURL_API_KEY_FILE: %#v", got)
	}
}

// With nothing configured the machine-wide path is still the answer, so existing
// installs that rely on it keep working unchanged.
func TestResolveCredentialsFallsBackToMachinePath(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, "")
	// Point HOME at an empty dir so the per-user file cannot be picked up.
	t.Setenv("HOME", t.TempDir())

	got, err := resolveCredentials("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fp, ok := got.(fileCredentialProvider)
	if !ok || fp.path != DefaultIssuerStatePath {
		t.Fatalf("did not fall back to the machine path: %#v", got)
	}
}

// The per-user file is the one the Connector installer writes with --token, so
// installing the Connector and using the SDK share a single credential.
func TestResolveCredentialsUsesConnectorInstallerPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, "")
	t.Setenv("HOME", home)
	want := writeTokenFile(t, home, UserIssuerStatePath)

	got, err := resolveCredentials("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fp, ok := got.(fileCredentialProvider)
	if !ok || fp.path != want {
		t.Fatalf("per-user connector token not used: %#v", got)
	}
}

// OpenClient is the entry point every issuing customer actually calls, and it
// had ZERO coverage: the tests above exercise resolveCredentials directly, so
// nothing proved the public API is wired to it. A regression that broke the
// wiring — rather than the resolver — would have passed the whole suite.

func TestOpenClientUsesAPIKeyFromEnvironment(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv(EnvAPIKey, "tok-from-env")
	t.Setenv(EnvAPIKeyFile, "")
	t.Setenv("HOME", t.TempDir())

	client, err := OpenClient(
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("OpenClient with QURL_API_KEY set: %v", err)
	}
	if client == nil {
		t.Fatal("OpenClient returned no client and no error")
	}
	// The startup check authorizes a synthetic request that is never sent, so
	// assert the credential reached the request builder rather than the wire.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("build probe request: %v", err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok-from-env" {
		t.Fatalf("Authorization = %q, want the env credential", got)
	}
	_ = gotAuth
}

// With nothing configured anywhere, OpenClient must fail with an actionable
// error rather than succeeding and failing later on the first real call.
func TestOpenClientWithNoCredentialFailsActionably(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, "")
	t.Setenv("HOME", t.TempDir())

	// Point the machine-wide path somewhere empty so the test never depends on
	// whether the host running it happens to have a real credential installed.
	_, err := OpenClient(WithIssuerStatePath(filepath.Join(t.TempDir(), "absent.json")))
	if err == nil {
		t.Fatal("OpenClient succeeded with no credential available")
	}
	if !errors.Is(err, ErrCredentialStateNotFound) && !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("error = %v; want a named credential error a customer can act on", err)
	}
}
