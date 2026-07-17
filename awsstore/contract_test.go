package awsstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

// storeContract captures the load-path behavior BOTH stores must honor
// identically. Each field seeds that store's in-memory fake for one scenario and
// returns the store under test as the qurl.AgentStateStore interface, so
// TestStoreContract exercises the same cases against both stores from one table
// instead of duplicating them per store. Genuinely store-specific plumbing (KMS
// binding, SecureString/Overwrite, create-race, parameter tier) stays in the
// per-store test files.
type storeContract struct {
	name string
	// roundTrip builds a fresh store over an empty backend that persists across a
	// Save then Load.
	roundTrip func() qurl.AgentStateStore
	// empty builds a store whose backend holds nothing (Load => not-found).
	empty func() qurl.AgentStateStore
	// stored builds a store whose backend holds the given raw value (present,
	// decodable or not).
	stored func(value string) qurl.AgentStateStore
	// noValue builds a store whose backend is present but carries a nil value
	// (Load => invalid-state).
	noValue func() qurl.AgentStateStore
	// loadErr builds a store whose Get fails with err (Load must fail closed).
	loadErr func(err error) qurl.AgentStateStore
}

func secretsManagerContract() storeContract {
	const id = "qurl/agent-state"
	return storeContract{
		name:      "SecretsManager",
		roundTrip: func() qurl.AgentStateStore { return awsstore.NewSecretsManagerStore(&fakeSecretsManager{}, id) },
		empty:     func() qurl.AgentStateStore { return awsstore.NewSecretsManagerStore(&fakeSecretsManager{}, id) },
		stored: func(value string) qurl.AgentStateStore {
			return awsstore.NewSecretsManagerStore(&fakeSecretsManager{exists: true, value: aws.String(value)}, id)
		},
		noValue: func() qurl.AgentStateStore {
			return awsstore.NewSecretsManagerStore(&fakeSecretsManager{exists: true, value: nil}, id)
		},
		loadErr: func(err error) qurl.AgentStateStore {
			return awsstore.NewSecretsManagerStore(&fakeSecretsManager{getErr: err}, id)
		},
	}
}

func parameterStoreContract() storeContract {
	const name = "/qurl/agent-state"
	return storeContract{
		name:      "ParameterStore",
		roundTrip: func() qurl.AgentStateStore { return awsstore.NewParameterStore(&fakeSSM{}, name) },
		empty:     func() qurl.AgentStateStore { return awsstore.NewParameterStore(&fakeSSM{}, name) },
		stored: func(value string) qurl.AgentStateStore {
			return awsstore.NewParameterStore(&fakeSSM{exists: true, value: aws.String(value)}, name)
		},
		noValue: func() qurl.AgentStateStore {
			return awsstore.NewParameterStore(&fakeSSM{exists: true, value: nil}, name)
		},
		loadErr: func(err error) qurl.AgentStateStore {
			return awsstore.NewParameterStore(&fakeSSM{getErr: err}, name)
		},
	}
}

// TestStoreContract holds both stores to the identical load-path contract.
func TestStoreContract(t *testing.T) {
	for _, c := range []storeContract{secretsManagerContract(), parameterStoreContract()} {
		t.Run(c.name, func(t *testing.T) {
			t.Run("RoundTrip", func(t *testing.T) {
				store := c.roundTrip()
				want := sampleState()
				if err := store.SaveAgentState(context.Background(), want); err != nil {
					t.Fatalf("save: %v", err)
				}
				got, err := store.LoadAgentState(context.Background())
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				assertStateEqual(t, want, got)
			})

			t.Run("NotFound", func(t *testing.T) {
				if _, err := c.empty().LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrAgentStateNotFound) {
					t.Fatalf("want ErrAgentStateNotFound, got %v", err)
				}
			})

			t.Run("CorruptValue", func(t *testing.T) {
				// A distinctive, secret-like corrupt blob: assert both the invalid-state
				// mapping AND that the decoder error never echoes stored bytes (the '~'
				// markers) into the error string.
				const corrupt = "~corrupt-secret-blob~"
				_, err := c.stored(corrupt).LoadAgentState(context.Background())
				if !errors.Is(err, qurl.ErrInvalidAgentState) {
					t.Fatalf("want ErrInvalidAgentState, got %v", err)
				}
				if strings.Contains(err.Error(), "~") {
					t.Fatalf("decode error must not embed stored bytes: %v", err)
				}
			})

			t.Run("NativeSchemaOnly", func(t *testing.T) {
				for name, raw := range map[string]string{
					"unknown field":           `{"private_key_b64":"x","public_key_b64":"y","retired_http_field":true}`,
					"trailing value":          `{"private_key_b64":"x","public_key_b64":"y"} {}`,
					"duplicate top-level key": `{"private_key_b64":"x","private_key_b64":"y","public_key_b64":"z"}`,
					"duplicate nested key":    `{"private_key_b64":"x","public_key_b64":"y","assignment":{"cell_id":"cell0","cell_id":"cell1"}}`,
				} {
					t.Run(name, func(t *testing.T) {
						if _, err := c.stored(raw).LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrInvalidAgentState) {
							t.Fatalf("want ErrInvalidAgentState, got %v", err)
						}
					})
				}
			})

			t.Run("NoValue", func(t *testing.T) {
				if _, err := c.noValue().LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrInvalidAgentState) {
					t.Fatalf("want ErrInvalidAgentState, got %v", err)
				}
			})

			t.Run("LoadGenericErrorFailsClosed", func(t *testing.T) {
				// A transient/non-sentinel backend failure must be surfaced wrapped, never
				// misclassified as not-found (fresh enrollment) or invalid-state (corrupt).
				_, err := c.loadErr(errBackend).LoadAgentState(context.Background())
				if err == nil {
					t.Fatal("expected a generic get error to be surfaced, got nil")
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
			})
		})
	}
}
