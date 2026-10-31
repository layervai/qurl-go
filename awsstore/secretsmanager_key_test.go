package awsstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

const verifiedKey = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

type describingSecrets struct {
	*fakeSecretsManager
	describe      func() (*secretsmanager.DescribeSecretOutput, error)
	describeCalls int
}

func (f *describingSecrets) DescribeSecret(_ context.Context, in *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	f.describeCalls++
	if aws.ToString(in.SecretId) != "agent" {
		return nil, errors.New("wrong secret ID")
	}
	return f.describe()
}

func TestSecretsManagerKeyVerification(t *testing.T) {
	denied := errors.New("describe denied")
	for _, tc := range []struct {
		name    string
		key     string
		output  *secretsmanager.DescribeSecretOutput
		err     error
		wantErr error
		wantPut bool
	}{
		{name: "match", key: verifiedKey, output: &secretsmanager.DescribeSecretOutput{KmsKeyId: aws.String(verifiedKey)}, wantPut: true},
		{name: "different key", key: verifiedKey, output: &secretsmanager.DescribeSecretOutput{KmsKeyId: aws.String(verifiedKey + "0")}, wantErr: qurl.ErrInvalidBootstrapConfig},
		{name: "AWS managed default", key: verifiedKey, output: &secretsmanager.DescribeSecretOutput{}, wantErr: qurl.ErrInvalidBootstrapConfig},
		{name: "nil output", key: verifiedKey, wantErr: qurl.ErrInvalidBootstrapConfig},
		{name: "permission denied", key: verifiedKey, err: denied, wantErr: denied},
		{name: "alias", key: "alias/agent", wantErr: qurl.ErrInvalidBootstrapConfig},
		{name: "missing configured key", wantErr: qurl.ErrInvalidBootstrapConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &describingSecrets{fakeSecretsManager: &fakeSecretsManager{exists: true, value: aws.String("old credential")}}
			fake.describe = func() (*secretsmanager.DescribeSecretOutput, error) { return tc.output, tc.err }
			store := awsstore.NewSecretsManagerStore(fake, "agent", awsstore.WithKMSKeyID(tc.key), awsstore.WithVerifyKMSKey())
			err := store.SaveAgentState(context.Background(), sampleState())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("save error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantPut {
				if fake.putCalls != 1 {
					t.Fatalf("puts=%d", fake.putCalls)
				}
			} else if fake.putCalls != 0 || fake.createCalls != 0 || aws.ToString(fake.value) != "old credential" {
				t.Fatal("failed verification changed credential")
			}
			if fake.getCalls != 0 {
				t.Fatal("verification loaded secret value")
			}
		})
	}
}

func TestSecretsManagerVerificationRequiresDescribeSupport(t *testing.T) {
	fake := &fakeSecretsManager{exists: true}
	err := awsstore.NewSecretsManagerStore(fake, "agent", awsstore.WithKMSKeyID(verifiedKey), awsstore.WithVerifyKMSKey()).SaveAgentState(context.Background(), sampleState())
	if !errors.Is(err, qurl.ErrInvalidBootstrapConfig) || fake.putCalls != 0 {
		t.Fatalf("error=%v puts=%d", err, fake.putCalls)
	}
}

func TestSecretsManagerVerifiedCreateAndCreateRace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		race  bool
		match bool
	}{
		{name: "new secret", match: true}, {name: "matching race winner", race: true, match: true}, {name: "wrong-key race winner", race: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &describingSecrets{fakeSecretsManager: &fakeSecretsManager{}}
			if tc.race {
				fake.createErr = &smtypes.ResourceExistsException{}
			}
			fake.describe = func() (*secretsmanager.DescribeSecretOutput, error) {
				if fake.describeCalls == 1 {
					return nil, &smtypes.ResourceNotFoundException{}
				}
				fake.exists = true
				key := verifiedKey
				if !tc.match {
					key = "other key"
				}
				return &secretsmanager.DescribeSecretOutput{KmsKeyId: aws.String(key)}, nil
			}
			err := awsstore.NewSecretsManagerStore(fake, "agent", awsstore.WithKMSKeyID(verifiedKey), awsstore.WithVerifyKMSKey()).SaveAgentState(context.Background(), sampleState())
			if tc.match && err != nil {
				t.Fatal(err)
			}
			if !tc.match && !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
				t.Fatalf("error=%v", err)
			}
			if fake.createCalls != 1 {
				t.Fatalf("creates=%d", fake.createCalls)
			}
			wantPuts := 0
			if tc.race && tc.match {
				wantPuts = 1
			}
			if fake.putCalls != wantPuts {
				t.Fatalf("puts=%d want %d", fake.putCalls, wantPuts)
			}
			if !tc.race && fake.createdKMS != verifiedKey {
				t.Fatal("created secret with wrong key")
			}
		})
	}
}

func TestSecretsManagerVerificationOptIn(t *testing.T) {
	fake := &describingSecrets{fakeSecretsManager: &fakeSecretsManager{exists: true}, describe: func() (*secretsmanager.DescribeSecretOutput, error) {
		t.Fatal("unexpected DescribeSecret")
		return nil, errors.New("unexpected DescribeSecret")
	}}
	if err := awsstore.NewSecretsManagerStore(fake, "agent").SaveAgentState(context.Background(), sampleState()); err != nil {
		t.Fatal(err)
	}
}
