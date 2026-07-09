package awsstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

// fakeSSM is an in-memory ParameterStoreAPI. It records the last PutParameter so
// tests can assert Type/Overwrite/KeyId plumbing, and honors an injected error
// or per-call hook.
type fakeSSM struct {
	exists bool
	value  *string

	lastPutType      ssmtypes.ParameterType
	lastPutOverwrite *bool
	lastPutKeyID     string
	lastGetDecrypt   *bool

	getErr error
	putErr error
	onCall func() error

	getCalls int
	putCalls int
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.getCalls++
	if f.onCall != nil {
		if err := f.onCall(); err != nil {
			return nil, err
		}
	}
	f.lastGetDecrypt = in.WithDecryption
	if f.getErr != nil {
		return nil, f.getErr
	}
	if !f.exists {
		return nil, &ssmtypes.ParameterNotFound{Message: aws.String("no such parameter")}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: f.value}}, nil
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.putCalls++
	if f.onCall != nil {
		if err := f.onCall(); err != nil {
			return nil, err
		}
	}
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.exists = true
	f.value = in.Value
	f.lastPutType = in.Type
	f.lastPutOverwrite = in.Overwrite
	f.lastPutKeyID = aws.ToString(in.KeyId)
	return &ssm.PutParameterOutput{}, nil
}

func TestParameterStore_RoundTrip(t *testing.T) {
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	want := sampleState()
	if err := store.SaveAgentState(context.Background(), want); err != nil {
		t.Fatalf("save: %v", err)
	}
	// SecureString + Overwrite are the required write shape.
	if fake.lastPutType != ssmtypes.ParameterTypeSecureString {
		t.Fatalf("want SecureString type, got %q", fake.lastPutType)
	}
	if !aws.ToBool(fake.lastPutOverwrite) {
		t.Fatalf("want Overwrite=true")
	}

	got, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	assertStateEqual(t, want, got)

	// Load must request decryption for the SecureString.
	if !aws.ToBool(fake.lastGetDecrypt) {
		t.Fatalf("want WithDecryption=true on GetParameter")
	}
}

func TestParameterStore_NotFound(t *testing.T) {
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrAgentStateNotFound) {
		t.Fatalf("want ErrAgentStateNotFound, got %v", err)
	}
}

func TestParameterStore_CorruptValue(t *testing.T) {
	fake := &fakeSSM{exists: true, value: aws.String("<<not json>>")}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("want ErrInvalidAgentState, got %v", err)
	}
}

func TestParameterStore_NoValue(t *testing.T) {
	fake := &fakeSSM{exists: true, value: nil}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("want ErrInvalidAgentState, got %v", err)
	}
}

func TestParameterStore_LoadGenericErrorFailsClosed(t *testing.T) {
	// errBackend (declared in secretsmanager_test.go) is a generic, non-sentinel
	// backend failure. A transient GetParameter error must fail closed: surfaced
	// wrapped, never misclassified as not-found or invalid-state.
	fake := &fakeSSM{getErr: errBackend}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if err == nil {
		t.Fatal("expected a generic GetParameter error to be surfaced, got nil")
	}
	if errors.Is(err, qurl.ErrAgentStateNotFound) {
		t.Fatalf("generic error must NOT be classified as ErrAgentStateNotFound: %v", err)
	}
	if errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("generic error must NOT be classified as ErrInvalidAgentState: %v", err)
	}
	if !errors.Is(err, errBackend) {
		t.Fatalf("underlying backend error not surfaced/wrapped: %v", err)
	}
}

func TestParameterStore_SaveGenericErrorSurfaced(t *testing.T) {
	fake := &fakeSSM{putErr: errBackend}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	err := store.SaveAgentState(context.Background(), sampleState())
	if err == nil {
		t.Fatal("expected a generic PutParameter error to be surfaced, got nil")
	}
	if !errors.Is(err, errBackend) {
		t.Fatalf("underlying put error not surfaced/wrapped: %v", err)
	}
}

func TestParameterStore_WithKMSKeyID(t *testing.T) {
	fake := &fakeSSM{}
	const keyID = "alias/qurl-agent"
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state", awsstore.WithKMSKeyID(keyID))

	if err := store.SaveAgentState(context.Background(), sampleState()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fake.lastPutKeyID != keyID {
		t.Fatalf("KMS key not plumbed to PutParameter: got %q want %q", fake.lastPutKeyID, keyID)
	}
}

func TestParameterStore_NilStateGuard(t *testing.T) {
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")
	if err := store.SaveAgentState(context.Background(), nil); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for nil state, got %v", err)
	}
	if fake.putCalls != 0 {
		t.Fatalf("nil-state guard should not call the API")
	}
}

func TestParameterStore_EmptyNameGuard(t *testing.T) {
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "")
	if err := store.SaveAgentState(context.Background(), sampleState()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for empty name on save, got %v", err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("want ErrInvalidBootstrapConfig for empty name on load, got %v", err)
	}
}

func TestParameterStore_ContextCancel(t *testing.T) {
	fake := &fakeSSM{exists: true, value: aws.String("{}")}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.LoadAgentState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("load: want context.Canceled, got %v", err)
	}
	if err := store.SaveAgentState(ctx, sampleState()); !errors.Is(err, context.Canceled) {
		t.Fatalf("save: want context.Canceled, got %v", err)
	}
	if fake.getCalls != 0 || fake.putCalls != 0 {
		t.Fatalf("cancelled context should not reach the API (get=%d put=%d)", fake.getCalls, fake.putCalls)
	}
}

func TestParameterStore_NilContextGuard(t *testing.T) {
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")
	//nolint:staticcheck // deliberately passing a nil context to exercise the guard.
	if _, err := store.LoadAgentState(nil); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("load: want ErrInvalidBootstrapConfig for nil ctx, got %v", err)
	}
	//nolint:staticcheck // deliberately passing a nil context to exercise the guard.
	if err := store.SaveAgentState(nil, sampleState()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("save: want ErrInvalidBootstrapConfig for nil ctx, got %v", err)
	}
	if fake.getCalls != 0 || fake.putCalls != 0 {
		t.Fatalf("nil context should not reach the API (get=%d put=%d)", fake.getCalls, fake.putCalls)
	}
}
