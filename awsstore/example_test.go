package awsstore_test

import (
	"context"
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

// These examples have no "// Output:" line, so the toolchain compiles them (they
// are checked by go vet / go test) but never runs them — nothing calls AWS. Real
// code builds the aws.Config with config.LoadDefaultConfig(ctx); the zero
// aws.Config here keeps the example dependency-light.

func ExampleNewSecretsManagerStore() {
	client := secretsmanager.NewFromConfig(aws.Config{})
	store := awsstore.NewSecretsManagerStore(
		client,
		"qurl/agent-state", // secret name or ARN
		awsstore.WithKMSKeyID("alias/qurl-agent"), // customer-managed CMK
	)

	ctx := context.Background()
	state, err := store.LoadAgentState(ctx)
	if errors.Is(err, qurl.ErrAgentStateNotFound) {
		// Nothing persisted yet: hand the store to qurl.ConnectAgentRuntime,
		// which enrolls over authenticated NHP UDP and saves state for you.
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	// Persist again, e.g. after a credential rotation.
	if err := store.SaveAgentState(ctx, state); err != nil {
		log.Fatal(err)
	}
}

func ExampleNewParameterStore() {
	client := ssm.NewFromConfig(aws.Config{})
	store := awsstore.NewParameterStore(
		client,
		"/qurl/agent-state", // parameter name
		awsstore.WithKMSKeyID("alias/qurl-agent"),                  // customer-managed CMK
		awsstore.WithParameterTier(ssmtypes.ParameterTierAdvanced), // 8 KB value ceiling
	)

	ctx := context.Background()
	state, err := store.LoadAgentState(ctx)
	if errors.Is(err, qurl.ErrAgentStateNotFound) {
		return // not enrolled yet; ConnectAgentRuntime enrolls and saves for you
	}
	if err != nil {
		log.Fatal(err)
	}
	if err := store.SaveAgentState(ctx, state); err != nil {
		log.Fatal(err)
	}
}

func ExampleNewKMSAgentStateKeyWrapper() {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(
		kms.NewFromConfig(cfg),
		"alias/qurl-agent-state",
	)
	if err != nil {
		log.Fatal(err)
	}
	store, err := qurl.NewSealedFileAgentState(
		"/var/lib/layerv/qurl/agent-state.sealed.json",
		"aws-kms",
		wrapper,
		qurl.WithExpectedSealedAgentID("connector-prod-1"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
}
