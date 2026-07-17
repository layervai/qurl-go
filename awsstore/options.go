package awsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

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
	// tier is the SSM parameter tier applied by [ParameterStore] on every
	// PutParameter. The zero value leaves Tier unset (the account's default tier
	// configuration). Ignored by [SecretsManagerStore].
	tier ssmtypes.ParameterTier
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

// WithParameterTier sets the SSM parameter tier [ParameterStore] applies on every
// PutParameter. The default (unset) uses the account's default tier
// configuration, whose standard tier caps a SecureString value at 4 KB. Because a
// registered AgentState carries a DeviceAPIKey, an unusually large token could
// push the JSON past 4 KB; pass [ssmtypes.ParameterTierAdvanced] to raise the
// ceiling to 8 KB. Note that promoting an existing standard parameter to advanced
// is a one-way, billable transition (advanced-tier parameters incur a per-parameter
// charge and cannot be downgraded in place), so weigh it against the 4 KB ceiling.
//
// This option applies only to [ParameterStore]; [SecretsManagerStore] ignores it.
// The zero-value tier leaves the field unset, preserving the prior behavior.
func WithParameterTier(tier ssmtypes.ParameterTier) Option {
	return func(c *storeConfig) {
		c.tier = tier
	}
}

// marshalAgentState guards a save request and encodes the state as JSON. It
// returns an ErrInvalidBootstrapConfig-wrapped error for a nil state or empty
// resource id so both stores share the same guard behavior.
func marshalAgentState(state *qurl.AgentState, resourceID, resourceLabel string) ([]byte, error) {
	if resourceID == "" {
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
// This separate module owns only the strict custody/decode boundary. Native
// assignment and pending-completion structural validation remains lifecycle-
// owned in qurl, which deliberately repeats it for every custom/network store.
func unmarshalAgentState(raw []byte) (*qurl.AgentState, error) {
	var state qurl.AgentState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// AgentState.UnmarshalJSON currently enforces exact fields itself. Keep this
	// as defense in depth if that custom decoder is ever removed; the trailing
	// Decode below remains independently load-bearing today.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("%w: decode agent state", qurl.ErrInvalidAgentState)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
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
