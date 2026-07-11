package awsstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/layervai/qurl-go/qurl"
)

// Option customizes a store constructed by [NewSecretsManagerStore] or
// [NewParameterStore]. It is a functional option shared by both stores; an
// option that does not apply to a given store is ignored by that store's
// constructor (documented per option).
type Option func(*storeConfig)

// storeConfig holds the resolved option state shared by both stores.
type storeConfig struct {
	// kmsKeyID is the customer-managed KMS key id/ARN/alias used to encrypt the
	// stored credential. Empty means the service default (AWS-managed) key.
	kmsKeyID string
}

func newStoreConfig(opts ...Option) storeConfig {
	var cfg storeConfig
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}
	return cfg
}

// WithKMSKeyID encrypts the stored credential with a customer-managed KMS key
// instead of the AWS-managed default key. keyID may be a key id, key ARN, or
// alias (for SSM, an alias must be prefixed "alias/").
//
//   - [SecretsManagerStore]: the key is applied when the secret is first created
//     (CreateSecret KmsKeyId). Secrets Manager's PutSecretValue has no KmsKeyId
//     field, so once a secret exists its encryption key is a property of the
//     secret; changing keys for an existing secret is an out-of-band
//     UpdateSecret operation. Set the key before the first save (or precreate the
//     secret with the desired key) to guarantee the credential is CMK-encrypted.
//   - [ParameterStore]: the key is applied on every PutParameter (KeyId) for the
//     SecureString, so it takes effect immediately on the next save.
//
// An empty keyID is ignored (the service default key is used).
func WithKMSKeyID(keyID string) Option {
	return func(c *storeConfig) {
		c.kmsKeyID = strings.TrimSpace(keyID)
	}
}

// marshalAgentState guards a save request and encodes the state as JSON. It
// returns an ErrInvalidBootstrapConfig-wrapped error for a nil state or empty
// resource id so both stores share the same guard behavior.
func marshalAgentState(state *qurl.AgentState, resourceID, resourceLabel string) ([]byte, error) {
	if strings.TrimSpace(resourceID) == "" {
		return nil, fmt.Errorf("%w: %s must not be empty", qurl.ErrInvalidBootstrapConfig, resourceLabel)
	}
	if state == nil {
		return nil, fmt.Errorf("%w: state must not be nil", qurl.ErrInvalidBootstrapConfig)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("qurl: encode agent state: %w", err)
	}
	return raw, nil
}

// unmarshalAgentState decodes a loaded value into an AgentState, mapping a decode
// failure to a wrapped [qurl.ErrInvalidAgentState] so callers' errors.Is matches.
func unmarshalAgentState(raw []byte) (*qurl.AgentState, error) {
	var state qurl.AgentState
	if err := json.Unmarshal(raw, &state); err != nil {
		// Deliberately do NOT %w the decoder error: encoding/json errors can embed
		// the offending input character/offset, and raw here is a decrypted
		// credential blob. Dropping the cause keeps stored bytes out of the error
		// string (and any logs it reaches) while errors.Is(ErrInvalidAgentState)
		// still matches for callers.
		return nil, fmt.Errorf("%w: decode agent state", qurl.ErrInvalidAgentState)
	}
	return &state, nil
}

// validateContext rejects a nil or already-cancelled context up front, mirroring
// the root package's helper of the same name and the file-backed store. Both
// LoadAgentState and SaveAgentState call it first so a cancelled context
// short-circuits uniformly before any argument validation or API call.
func validateContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", qurl.ErrInvalidBootstrapConfig)
	}
	return ctx.Err()
}
