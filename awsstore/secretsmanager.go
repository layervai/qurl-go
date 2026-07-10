package awsstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/layervai/qurl-go/qurl"
)

// SecretsManagerAPI is the narrow slice of the AWS Secrets Manager client that
// [SecretsManagerStore] uses. The concrete *secretsmanager.Client satisfies it,
// and a fake satisfies it in tests, so the full SDK surface is never a dependency
// of callers or of the test.
type SecretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
}

// Compile-time proof the real client satisfies the narrow interface.
var _ SecretsManagerAPI = (*secretsmanager.Client)(nil)

// SecretsManagerStore is a [qurl.AgentStateStore] backed by an AWS Secrets
// Manager secret. The agent state is stored as the secret's SecretString (JSON).
//
// SECURITY: the stored value is a credential. Prefer a customer-managed KMS key
// via [WithKMSKeyID] and least-privilege IAM (GetSecretValue, PutSecretValue,
// CreateSecret on the one secret ARN). See the package doc.
type SecretsManagerStore struct {
	client   SecretsManagerAPI
	secretID string
	kmsKeyID string
}

var _ qurl.AgentStateStore = (*SecretsManagerStore)(nil)

// NewSecretsManagerStore returns a [qurl.AgentStateStore] that persists the agent
// state in the Secrets Manager secret named or ARNed by secretID, using client
// for API calls. Pass [WithKMSKeyID] to encrypt a newly created secret with a
// customer-managed key.
//
// secretID may be a secret name or a full ARN for load and update. Auto-create
// (the first save when the secret does not exist) requires a NAME, since
// CreateSecret takes a friendly name, not an ARN — if secretID is an ARN, the
// secret must already exist.
func NewSecretsManagerStore(client SecretsManagerAPI, secretID string, opts ...Option) *SecretsManagerStore {
	cfg := newStoreConfig(opts...)
	return &SecretsManagerStore{
		client:   client,
		secretID: secretID,
		kmsKeyID: cfg.kmsKeyID,
	}
}

// LoadAgentState fetches the secret and decodes its SecretString into an
// AgentState. A missing secret maps to [qurl.ErrAgentStateNotFound]; a present
// but undecodable SecretString maps to [qurl.ErrInvalidAgentState].
func (s *SecretsManagerStore) LoadAgentState(ctx context.Context) (*qurl.AgentState, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if s.client == nil {
		return nil, fmt.Errorf("%w: secrets manager client must not be nil", qurl.ErrInvalidBootstrapConfig)
	}
	if strings.TrimSpace(s.secretID) == "" {
		return nil, fmt.Errorf("%w: secret id must not be empty", qurl.ErrInvalidBootstrapConfig)
	}

	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.secretID),
	})
	if err != nil {
		// A secret that has never been created reads as "not registered yet".
		var notFound *smtypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, qurl.ErrAgentStateNotFound
		}
		return nil, fmt.Errorf("qurl: get secret value: %w", err)
	}
	if out.SecretString == nil {
		// The secret exists but has no string value (e.g. binary-only). Treat a
		// present-but-unreadable value as corrupt, not as "not found".
		return nil, fmt.Errorf("%w: secret has no string value", qurl.ErrInvalidAgentState)
	}
	return unmarshalAgentState([]byte(*out.SecretString))
}

// SaveAgentState marshals state to JSON and upserts it into the secret: it tries
// PutSecretValue first, and on ResourceNotFoundException creates the secret
// (CreateSecret) with the configured KMS key, then is idempotent thereafter.
func (s *SecretsManagerStore) SaveAgentState(ctx context.Context, state *qurl.AgentState) error {
	// Context first so a cancelled ctx short-circuits uniformly with Load.
	if err := validateContext(ctx); err != nil {
		return err
	}
	raw, err := marshalAgentState(state, s.secretID, "secret id")
	if err != nil {
		return err
	}
	if s.client == nil {
		return fmt.Errorf("%w: secrets manager client must not be nil", qurl.ErrInvalidBootstrapConfig)
	}

	secretString := string(raw)
	_, err = s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(s.secretID),
		SecretString: aws.String(secretString),
	})
	if err == nil {
		return nil
	}

	// First write for this secret id: create it. CreateSecret is where the
	// customer-managed KMS key is bound (PutSecretValue has no KmsKeyId field).
	var notFound *smtypes.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		return fmt.Errorf("qurl: put secret value: %w", err)
	}
	in := &secretsmanager.CreateSecretInput{
		Name:         aws.String(s.secretID),
		SecretString: aws.String(secretString),
	}
	if s.kmsKeyID != "" {
		in.KmsKeyId = aws.String(s.kmsKeyID)
	}
	if _, err := s.client.CreateSecret(ctx, in); err != nil {
		// Lost a create race with a concurrent writer: fall back to a put so the
		// value still lands. Any other create failure surfaces.
		//
		// KMS caveat: PutSecretValue cannot set KmsKeyId, so on this path the value
		// persists under whatever key the winning CreateSecret chose. If that writer
		// used a different or the AWS-managed default key, the credential is NOT
		// encrypted under our configured CMK here — inherent to the API (the key is
		// a property of the secret, bound at create; see WithKMSKeyID's doc).
		var exists *smtypes.ResourceExistsException
		if errors.As(err, &exists) {
			if _, perr := s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
				SecretId:     aws.String(s.secretID),
				SecretString: aws.String(secretString),
			}); perr != nil {
				return fmt.Errorf("qurl: put secret value after create race: %w", perr)
			}
			return nil
		}
		return fmt.Errorf("qurl: create secret: %w", err)
	}
	return nil
}
