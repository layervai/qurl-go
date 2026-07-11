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
	exists       bool
	value        *string
	nilParameter bool // if set, GetParameter returns a success with a nil Parameter

	lastPutType      ssmtypes.ParameterType
	lastPutOverwrite *bool
	lastPutKeyID     string
	lastPutTier      ssmtypes.ParameterTier
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
	if f.nilParameter {
		// A success response that carries no Parameter object at all.
		return &ssm.GetParameterOutput{Parameter: nil}, nil
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
	f.lastPutTier = in.Tier
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

// Load-path mapping cases (not-found, corrupt value, no value, generic-error
// fails closed) are consolidated in TestStoreContract (contract_test.go), which
// runs the identical table against both stores. The tests below cover the SSM
// parameter-specific plumbing (SecureString/Overwrite/decryption, tier, KMS key)
// and the nil-Parameter sub-branch that has no Secrets Manager analogue.

func TestParameterStore_NilParameterIsNotFound(t *testing.T) {
	// A GetParameter success carrying a nil Parameter object has nothing stored;
	// the store maps it to ErrAgentStateNotFound (same as ParameterNotFound),
	// distinct from the Value-nil corrupt case exercised by TestStoreContract.
	fake := &fakeSSM{exists: true, nilParameter: true}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	_, err := store.LoadAgentState(context.Background())
	if !errors.Is(err, qurl.ErrAgentStateNotFound) {
		t.Fatalf("want ErrAgentStateNotFound for a nil Parameter, got %v", err)
	}
}

func TestParameterStore_NilClientFailsClosed(t *testing.T) {
	// A store constructed with a nil client must fail closed on both methods with
	// ErrInvalidBootstrapConfig rather than panic on the first API call.
	store := awsstore.NewParameterStore(nil, "/qurl/agent-state")
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("load: want ErrInvalidBootstrapConfig for nil client, got %v", err)
	}
	if err := store.SaveAgentState(context.Background(), sampleState()); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("save: want ErrInvalidBootstrapConfig for nil client, got %v", err)
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

func TestParameterStore_WithParameterTier(t *testing.T) {
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state", awsstore.WithParameterTier(ssmtypes.ParameterTierAdvanced))

	if err := store.SaveAgentState(context.Background(), sampleState()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fake.lastPutTier != ssmtypes.ParameterTierAdvanced {
		t.Fatalf("tier not plumbed to PutParameter: got %q want %q", fake.lastPutTier, ssmtypes.ParameterTierAdvanced)
	}
}

func TestParameterStore_DefaultTierUnset(t *testing.T) {
	// Without WithParameterTier the Tier field stays the zero value, so AWS uses
	// the account's default tier configuration (prior behavior).
	fake := &fakeSSM{}
	store := awsstore.NewParameterStore(fake, "/qurl/agent-state")

	if err := store.SaveAgentState(context.Background(), sampleState()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fake.lastPutTier != "" {
		t.Fatalf("default tier must be unset, got %q", fake.lastPutTier)
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
