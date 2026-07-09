package awsstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

// fakeSecretsManager is an in-memory SecretsManagerAPI. A zero value has no
// stored secret; the first CreateSecret (or PutSecretValue on the create-race
// path) materializes it. It records the KMS key id passed to CreateSecret so a
// test can assert WithKMSKeyID plumbing.
type fakeSecretsManager struct {
	exists     bool
	value      *string
	createdKMS string

	// Injected failures / hooks.
	getErr    error
	putErr    error
	createErr error
	onCall    func() error // consulted at the top of every method (e.g. ctx check)

	getCalls    int
	putCalls    int
	createCalls int
}

func (f *fakeSecretsManager) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.getCalls++
	if f.onCall != nil {
		if err := f.onCall(); err != nil {
			return nil, err
		}
	}
	if f.getErr != nil {
		return nil, f.getErr
	}
	if !f.exists {
		return nil, &smtypes.ResourceNotFoundException{Message: aws.String("no such secret")}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: f.value}, nil
}

func (f *fakeSecretsManager) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.putCalls++
	if f.onCall != nil {
		if err := f.onCall(); err != nil {
			return nil, err
		}
	}
	if f.putErr != nil {
		return nil, f.putErr
	}
	if !f.exists {
		return nil, &smtypes.ResourceNotFoundException{Message: aws.String("no such secret")}
	}
	f.value = in.SecretString
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeSecretsManager) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.createCalls++
	if f.onCall != nil {
		if err := f.onCall(); err != nil {
			return nil, err
		}
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.exists {
		return nil, &smtypes.ResourceExistsException{Message: aws.String("already exists")}
	}
	f.exists = true
	f.value = in.SecretString
	f.createdKMS = aws.ToString(in.KmsKeyId)
	return &secretsmanager.CreateSecretOutput{}, nil
}

func sampleState() *qurl.AgentState {
	ts := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	return &qurl.AgentState{
		AgentID:       "agent-123",
		PrivateKeyB64: "cHJpdmF0ZS1rZXk=",
		PublicKeyB64:  "cHVibGljLWtleQ==",
		RegisteredAt:  &ts,
		DeviceAPIKey:  "dev-secret-bearer",
		SchemaVersion: 2,
		NHPPeer: &qurl.NHPServerPeerInfo{
			PublicKeyB64: "cGVlci1rZXk=",
			Host:         "relay.example.com",
			Port:         443,
		},
	}
}

func assertStateEqual(t *testing.T, want, got *qurl.AgentState) {
	t.Helper()
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("state mismatch:\n want %s\n  got %s", wantJSON, gotJSON)
	}
}

func TestSecretsManagerStore_RoundTrip(t *testing.T) {
	fake := &fakeSecretsManager{}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	want := sampleState()
	if err := store.SaveAgentState(context.Background(), want); err != nil {
		t.Fatalf("save: %v", err)
	}
	// First save on a missing secret creates it.
	if fake.createCalls != 1 {
		t.Fatalf("expected 1 CreateSecret call, got %d", fake.createCalls)
	}

	got, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	assertStateEqual(t, want, got)

	// A second save updates in place via PutSecretValue (no second create).
	want.DeviceAPIKey = "rotated-bearer"
	if err := store.SaveAgentState(context.Background(), want); err != nil {
		t.Fatalf("second save: %v", err)
	}
	if fake.createCalls != 1 {
		t.Fatalf("expected still 1 CreateSecret call, got %d", fake.createCalls)
	}
	got, err = store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load after update: %v", err)
	}
	assertStateEqual(t, want, got)
}

func TestSecretsManagerStore_NotFound(t *testing.T) {
	fake := &fakeSecretsManager{} // no secret stored
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrAgentStateNotFound) {
		t.Fatalf("want ErrAgentStateNotFound, got %v", err)
	}
}

func TestSecretsManagerStore_CorruptValue(t *testing.T) {
	fake := &fakeSecretsManager{exists: true, value: aws.String("{not valid json")}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("want ErrInvalidAgentState, got %v", err)
	}
}

func TestSecretsManagerStore_NoStringValue(t *testing.T) {
	// Secret exists but SecretString is nil (binary-only) -> treated as corrupt.
	fake := &fakeSecretsManager{exists: true, value: nil}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("want ErrInvalidAgentState, got %v", err)
	}
}

// errBackend is a generic, NON-sentinel backend failure (e.g. AccessDenied or a
// throttle) used to prove that a transient API error fails closed: it must be
// surfaced wrapped, never misclassified as not-found or invalid-state.
var errBackend = errors.New("AccessDeniedException: denied")

func TestSecretsManagerStore_LoadGenericErrorFailsClosed(t *testing.T) {
	fake := &fakeSecretsManager{getErr: errBackend}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if err == nil {
		t.Fatal("expected a generic GetSecretValue error to be surfaced, got nil")
	}
	// The safety property: a transient failure is NOT a fresh-enrollment signal
	// and NOT a corrupt-state signal.
	if errors.Is(err, qurl.ErrAgentStateNotFound) {
		t.Fatalf("generic error must NOT be classified as ErrAgentStateNotFound: %v", err)
	}
	if errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("generic error must NOT be classified as ErrInvalidAgentState: %v", err)
	}
	// The underlying cause stays reachable (wrapped with %w).
	if !errors.Is(err, errBackend) {
		t.Fatalf("underlying backend error not surfaced/wrapped: %v", err)
	}
}

func TestSecretsManagerStore_SaveGenericErrorSurfaced(t *testing.T) {
	// PutSecretValue fails with a generic error on an existing secret: it must be
	// surfaced (not swallowed, not treated as not-found -> create).
	fake := &fakeSecretsManager{exists: true, value: aws.String("{}"), putErr: errBackend}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	err := store.SaveAgentState(context.Background(), sampleState())
	if err == nil {
		t.Fatal("expected a generic PutSecretValue error to be surfaced, got nil")
	}
	if !errors.Is(err, errBackend) {
		t.Fatalf("underlying put error not surfaced/wrapped: %v", err)
	}
	// A generic (non not-found) put error must not trigger the create path.
	if fake.createCalls != 0 {
		t.Fatalf("generic put error must not fall through to CreateSecret, got %d create calls", fake.createCalls)
	}
}

func TestSecretsManagerStore_WithKMSKeyID(t *testing.T) {
	fake := &fakeSecretsManager{}
	const keyID = "arn:aws:kms:us-east-1:111122223333:key/abcd"
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state", awsstore.WithKMSKeyID(keyID))

	if err := store.SaveAgentState(context.Background(), sampleState()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fake.createdKMS != keyID {
		t.Fatalf("KMS key not plumbed to CreateSecret: got %q want %q", fake.createdKMS, keyID)
	}
}

func TestSecretsManagerStore_CreateRaceFallsBackToPut(t *testing.T) {
	// Simulate the create race: our first Put sees no secret (not-found), our
	// Create then loses to a concurrent writer (ResourceExistsException), and the
	// store must fall back to a second Put that lands the value.
	//
	// Sequencing via a call counter: put#1 -> not-found, create#1 -> exists,
	// put#2 -> success. `exists` starts false so put#1 returns not-found through
	// the fake's own logic; create#1 is forced to fail with exists; before the
	// fallback put we flip `exists` true so put#2 succeeds.
	fake := &fakeSecretsManager{}
	fake.createErr = &smtypes.ResourceExistsException{Message: aws.String("raced")}
	fake.onCall = func() error {
		// After the create attempt has been counted, mark the secret existing so
		// the fallback Put (put#2) succeeds.
		if fake.createCalls == 1 {
			fake.exists = true
		}
		return nil
	}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")
	if err := store.SaveAgentState(context.Background(), sampleState()); err != nil {
		t.Fatalf("save with create race: %v", err)
	}
	if fake.putCalls != 2 {
		t.Fatalf("expected a fallback PutSecretValue (2 puts total), got %d", fake.putCalls)
	}
	if fake.createCalls != 1 {
		t.Fatalf("expected exactly 1 CreateSecret attempt, got %d", fake.createCalls)
	}
}

func TestSecretsManagerStore_NilStateGuard(t *testing.T) {
	fake := &fakeSecretsManager{}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")
	err := store.SaveAgentState(context.Background(), nil)
	if !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for nil state, got %v", err)
	}
	if fake.putCalls != 0 || fake.createCalls != 0 {
		t.Fatalf("nil-state guard should not call the API")
	}
}

func TestSecretsManagerStore_EmptySecretIDGuard(t *testing.T) {
	fake := &fakeSecretsManager{}
	store := awsstore.NewSecretsManagerStore(fake, "")
	if err := store.SaveAgentState(context.Background(), sampleState()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for empty secret id on save, got %v", err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for empty secret id on load, got %v", err)
	}
}

func TestSecretsManagerStore_ContextCancel(t *testing.T) {
	fake := &fakeSecretsManager{exists: true, value: aws.String("{}")}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.LoadAgentState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("load: want context.Canceled, got %v", err)
	}
	if err := store.SaveAgentState(ctx, sampleState()); !errors.Is(err, context.Canceled) {
		t.Fatalf("save: want context.Canceled, got %v", err)
	}
	// A cancelled context must short-circuit before any API call.
	if fake.getCalls != 0 || fake.putCalls != 0 || fake.createCalls != 0 {
		t.Fatalf("cancelled context should not reach the API (get=%d put=%d create=%d)", fake.getCalls, fake.putCalls, fake.createCalls)
	}
}

func TestSecretsManagerStore_NilContextGuard(t *testing.T) {
	fake := &fakeSecretsManager{}
	store := awsstore.NewSecretsManagerStore(fake, "qurl/agent-state")
	//nolint:staticcheck // deliberately passing a nil context to exercise the guard.
	if _, err := store.LoadAgentState(nil); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for nil ctx, got %v", err)
	}
}
