package awsstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/layervai/qurl-go/qurl"
)

// ParameterStoreAPI is the narrow slice of the AWS SSM client that
// [ParameterStore] uses. The concrete *ssm.Client satisfies it, and a fake
// satisfies it in tests, so the full SDK surface is never a dependency of callers
// or of the test.
type ParameterStoreAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// Compile-time proof the real client satisfies the narrow interface.
var _ ParameterStoreAPI = (*ssm.Client)(nil)

// ParameterStore is a [qurl.AgentStateStore] backed by an AWS Systems Manager
// (SSM) Parameter Store SecureString. The agent state is stored as the
// parameter's Value (JSON), encrypted at rest by KMS.
//
// SECURITY: the stored value is a credential. Prefer a customer-managed KMS key
// via [WithKMSKeyID] and least-privilege IAM (GetParameter, PutParameter on the
// one parameter ARN). See the package doc.
type ParameterStore struct {
	client   ParameterStoreAPI
	name     string
	kmsKeyID string
}

var _ qurl.AgentStateStore = (*ParameterStore)(nil)

// NewParameterStore returns a [qurl.AgentStateStore] that persists the agent
// state in the SSM parameter named name, using client for API calls. Pass
// [WithKMSKeyID] to encrypt the SecureString with a customer-managed key on every
// write.
func NewParameterStore(client ParameterStoreAPI, name string, opts ...Option) *ParameterStore {
	cfg := newStoreConfig(opts...)
	return &ParameterStore{
		client:   client,
		name:     strings.TrimSpace(name),
		kmsKeyID: cfg.kmsKeyID,
	}
}

// LoadAgentState fetches the parameter with decryption and decodes its Value into
// an AgentState. A missing parameter maps to [qurl.ErrAgentStateNotFound]; a
// present but undecodable Value maps to [qurl.ErrInvalidAgentState].
func (s *ParameterStore) LoadAgentState(ctx context.Context) (*qurl.AgentState, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if s.client == nil {
		return nil, fmt.Errorf("%w: ssm client must not be nil", qurl.ErrInvalidBootstrapConfig)
	}
	if strings.TrimSpace(s.name) == "" {
		return nil, fmt.Errorf("%w: parameter name must not be empty", qurl.ErrInvalidBootstrapConfig)
	}

	out, err := s.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(s.name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		// A parameter that has never been written reads as "not registered yet".
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return nil, qurl.ErrAgentStateNotFound
		}
		return nil, fmt.Errorf("qurl: get parameter: %w", err)
	}
	if out.Parameter == nil {
		// A success response that carries no Parameter object has nothing stored;
		// treat it as "not registered yet", the same as ParameterNotFound.
		return nil, qurl.ErrAgentStateNotFound
	}
	if out.Parameter.Value == nil {
		// The parameter exists but holds no value: present-but-unreadable, so map
		// it to invalid-state (corrupt), distinct from the not-found case above.
		return nil, fmt.Errorf("%w: parameter has no value", qurl.ErrInvalidAgentState)
	}
	return unmarshalAgentState([]byte(*out.Parameter.Value))
}

// SaveAgentState marshals state to JSON and writes it as a SecureString
// parameter, overwriting any existing value. The configured KMS key (if any) is
// applied on every write.
func (s *ParameterStore) SaveAgentState(ctx context.Context, state *qurl.AgentState) error {
	// Guard order mirrors LoadAgentState exactly (context, then nil-client, then
	// the id/state marshal guard) so a given misconfiguration yields the same
	// human-facing message from both methods.
	if err := validateContext(ctx); err != nil {
		return err
	}
	if s.client == nil {
		return fmt.Errorf("%w: ssm client must not be nil", qurl.ErrInvalidBootstrapConfig)
	}
	raw, err := marshalAgentState(state, s.name, "parameter name")
	if err != nil {
		return err
	}

	in := &ssm.PutParameterInput{
		Name:      aws.String(s.name),
		Value:     aws.String(string(raw)),
		Type:      ssmtypes.ParameterTypeSecureString,
		Overwrite: aws.Bool(true),
	}
	if s.kmsKeyID != "" {
		in.KeyId = aws.String(s.kmsKeyID)
	}
	if _, err := s.client.PutParameter(ctx, in); err != nil {
		return fmt.Errorf("qurl: put parameter: %w", err)
	}
	return nil
}
