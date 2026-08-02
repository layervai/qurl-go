package awsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/layervai/qurl-go/qurl"
)

const (
	kmsAgentStateWrappedKeyVersion = 1
	kmsAgentStateDEKBytes          = 32
	maxKMSAgentStateKeyIDBytes     = 2048

	// KMSAgentStateContextPurpose is the encryption-context key that binds a
	// wrapped DEK to qurl.AgentStateKeyBinding.Purpose.
	KMSAgentStateContextPurpose = "qurl_purpose"
	// KMSAgentStateContextEnvelopeVersion is the encryption-context key that
	// binds a wrapped DEK to qurl.AgentStateKeyBinding.EnvelopeVersion.
	KMSAgentStateContextEnvelopeVersion = "qurl_envelope_version"
	// KMSAgentStateContextProviderID is the encryption-context key that binds a
	// wrapped DEK to qurl.AgentStateKeyBinding.ProviderID.
	KMSAgentStateContextProviderID = "qurl_provider_id"
	// KMSAgentStateContextAgentID is the encryption-context key that binds a
	// wrapped DEK to qurl.AgentStateKeyBinding.AgentID.
	KMSAgentStateContextAgentID = "qurl_agent_id"
)

// KMSAPI is the exact AWS KMS surface used by KMSAgentStateKeyWrapper.
// A *kms.Client satisfies it.
type KMSAPI interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

var _ KMSAPI = (*kms.Client)(nil)

var kmsKeyResourcePattern = regexp.MustCompile(`^key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

// KMSAgentStateKeyWrapper wraps each qurl sealed-state data key with one AWS
// KMS symmetric key. It sends every AgentStateKeyBinding field as KMS encryption
// context, and supplies the exact KMS key ARN returned by Encrypt back to
// Decrypt. The complete AgentState never crosses this boundary.
type KMSAgentStateKeyWrapper struct {
	client KMSAPI
	keyID  string
}

var _ qurl.AgentStateKeyWrapper = (*KMSAgentStateKeyWrapper)(nil)

// NewKMSAgentStateKeyWrapper constructs an AWS KMS wrapper for
// qurl.NewSealedFileAgentState. keyID may be a key ARN, key id, or alias accepted
// by KMS. Each successful wrap persists the exact key ARN returned by KMS, so a
// later unwrap is pinned to that key even if a configured alias is retargeted.
func NewKMSAgentStateKeyWrapper(client KMSAPI, keyID string) (*KMSAgentStateKeyWrapper, error) {
	if isNilKMSAPI(client) {
		return nil, fmt.Errorf("%w: KMS client must not be nil", qurl.ErrInvalidBootstrapConfig)
	}
	if err := validateConfiguredKMSKeyID(keyID); err != nil {
		return nil, err
	}
	return &KMSAgentStateKeyWrapper{client: client, keyID: keyID}, nil
}

// WrapKey encrypts one 32-byte sealed-state DEK under the configured KMS key.
func (w *KMSAgentStateKeyWrapper) WrapKey(ctx context.Context, plaintextKey []byte, binding qurl.AgentStateKeyBinding) (qurl.WrappedAgentStateKey, error) {
	if err := validateContext(ctx); err != nil {
		return qurl.WrappedAgentStateKey{}, err
	}
	if w == nil || isNilKMSAPI(w.client) {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("%w: KMS key wrapper is not configured", qurl.ErrInvalidBootstrapConfig)
	}
	if len(plaintextKey) != kmsAgentStateDEKBytes {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("%w: sealed-state DEK must be exactly %d bytes", qurl.ErrInvalidBootstrapConfig, kmsAgentStateDEKBytes)
	}
	encryptionContext, err := kmsAgentStateEncryptionContext(binding)
	if err != nil {
		return qurl.WrappedAgentStateKey{}, err
	}

	kmsPlaintext := bytes.Clone(plaintextKey)
	defer clear(kmsPlaintext)
	out, err := w.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               aws.String(w.keyID),
		Plaintext:           kmsPlaintext,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   encryptionContext,
	})
	if err != nil {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("awsstore: encrypt sealed-state DEK: %w", err)
	}
	if out == nil || len(out.CiphertextBlob) == 0 {
		return qurl.WrappedAgentStateKey{}, errors.New("awsstore: KMS Encrypt returned no ciphertext")
	}
	keyARN, err := canonicalKMSKeyARN(aws.ToString(out.KeyId))
	if err != nil {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("awsstore: KMS Encrypt returned an invalid key id: %w", err)
	}
	metadata, err := json.Marshal(kmsAgentStateWrappedKeyMetadata{KeyID: keyARN})
	if err != nil {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("awsstore: encode KMS wrapped-key metadata: %w", err)
	}
	return qurl.WrappedAgentStateKey{
		Version:    kmsAgentStateWrappedKeyVersion,
		Ciphertext: bytes.Clone(out.CiphertextBlob),
		Metadata:   metadata,
	}, nil
}

// UnwrapKey decrypts one KMS-wrapped sealed-state DEK under the authenticated
// binding. KMS ciphertext/key-binding failures map to
// qurl.ErrInvalidWrappedAgentStateKey; IAM, network, throttling, and key-state
// failures remain operational errors.
func (w *KMSAgentStateKeyWrapper) UnwrapKey(ctx context.Context, wrapped qurl.WrappedAgentStateKey, binding qurl.AgentStateKeyBinding) ([]byte, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if w == nil || isNilKMSAPI(w.client) {
		return nil, fmt.Errorf("%w: KMS key wrapper is not configured", qurl.ErrInvalidBootstrapConfig)
	}
	if wrapped.Version != kmsAgentStateWrappedKeyVersion || len(wrapped.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: invalid KMS wrapped-key record", qurl.ErrInvalidWrappedAgentStateKey)
	}
	metadata, err := decodeKMSAgentStateWrappedKeyMetadata(wrapped.Metadata)
	if err != nil {
		return nil, err
	}
	encryptionContext, err := kmsAgentStateEncryptionContext(binding)
	if err != nil {
		return nil, err
	}

	kmsCiphertext := bytes.Clone(wrapped.Ciphertext)
	defer clear(kmsCiphertext)
	out, err := w.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:      kmsCiphertext,
		KeyId:               aws.String(metadata.KeyID),
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   encryptionContext,
	})
	if err != nil {
		var invalidCiphertext *kmstypes.InvalidCiphertextException
		var incorrectKey *kmstypes.IncorrectKeyException
		if errors.As(err, &invalidCiphertext) || errors.As(err, &incorrectKey) {
			return nil, fmt.Errorf("%w: KMS rejected the ciphertext binding", qurl.ErrInvalidWrappedAgentStateKey)
		}
		return nil, fmt.Errorf("awsstore: decrypt sealed-state DEK: %w", err)
	}
	if out == nil {
		return nil, errors.New("awsstore: KMS Decrypt returned no result")
	}
	if aws.ToString(out.KeyId) != metadata.KeyID || len(out.Plaintext) != kmsAgentStateDEKBytes {
		clear(out.Plaintext)
		return nil, fmt.Errorf("%w: KMS returned a mismatched key or plaintext length", qurl.ErrInvalidWrappedAgentStateKey)
	}
	return out.Plaintext, nil
}

type kmsAgentStateWrappedKeyMetadata struct {
	KeyID string `json:"key_id"`
}

func decodeKMSAgentStateWrappedKeyMetadata(raw json.RawMessage) (kmsAgentStateWrappedKeyMetadata, error) {
	var metadata kmsAgentStateWrappedKeyMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || decoder.Decode(&metadata) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return metadata, fmt.Errorf("%w: invalid KMS wrapped-key metadata", qurl.ErrInvalidWrappedAgentStateKey)
	}
	keyARN, err := canonicalKMSKeyARN(metadata.KeyID)
	if err != nil || keyARN != metadata.KeyID {
		return metadata, fmt.Errorf("%w: invalid KMS wrapped-key key id", qurl.ErrInvalidWrappedAgentStateKey)
	}
	return metadata, nil
}

func kmsAgentStateEncryptionContext(binding qurl.AgentStateKeyBinding) (map[string]string, error) {
	if err := validateKMSBindingField("purpose", binding.Purpose, 128); err != nil {
		return nil, err
	}
	if binding.EnvelopeVersion < 1 {
		return nil, fmt.Errorf("%w: envelope version must be positive", qurl.ErrInvalidBootstrapConfig)
	}
	if err := validateKMSBindingField("provider id", binding.ProviderID, 64); err != nil {
		return nil, err
	}
	if err := validateKMSBindingField("agent id", binding.AgentID, 256); err != nil {
		return nil, err
	}
	return map[string]string{
		KMSAgentStateContextPurpose:         binding.Purpose,
		KMSAgentStateContextEnvelopeVersion: strconv.Itoa(binding.EnvelopeVersion),
		KMSAgentStateContextProviderID:      binding.ProviderID,
		KMSAgentStateContextAgentID:         binding.AgentID,
	}, nil
}

func validateKMSBindingField(name, value string, maximum int) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maximum || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: KMS binding %s must be canonical, non-empty, and at most %d bytes", qurl.ErrInvalidBootstrapConfig, name, maximum)
	}
	return nil
}

func validateConfiguredKMSKeyID(keyID string) error {
	if keyID == "" || keyID != strings.TrimSpace(keyID) || len(keyID) > maxKMSAgentStateKeyIDBytes || strings.IndexFunc(keyID, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: KMS key id must be canonical, non-empty, and at most %d bytes", qurl.ErrInvalidBootstrapConfig, maxKMSAgentStateKeyIDBytes)
	}
	return nil
}

func canonicalKMSKeyARN(value string) (string, error) {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Service != "kms" || parsed.Partition == "" || parsed.Region == "" || parsed.AccountID == "" ||
		!kmsKeyResourcePattern.MatchString(parsed.Resource) {
		return "", errors.New("expected an exact KMS key ARN")
	}
	return parsed.String(), nil
}

func isNilKMSAPI(client KMSAPI) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
