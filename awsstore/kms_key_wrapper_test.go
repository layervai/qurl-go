package awsstore_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

const testKMSKeyARN = "arn:aws:kms:us-east-2:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

type fakeKMS struct {
	encryptInput *kms.EncryptInput
	decryptInput *kms.DecryptInput
	encryptOut   *kms.EncryptOutput
	decryptOut   *kms.DecryptOutput
	encryptErr   error
	decryptErr   error
}

func (f *fakeKMS) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	captured := *input
	captured.KeyId = aws.String(aws.ToString(input.KeyId))
	captured.Plaintext = bytes.Clone(input.Plaintext)
	captured.EncryptionContext = maps.Clone(input.EncryptionContext)
	f.encryptInput = &captured
	return f.encryptOut, f.encryptErr
}

func (f *fakeKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	captured := *input
	captured.KeyId = aws.String(aws.ToString(input.KeyId))
	captured.CiphertextBlob = bytes.Clone(input.CiphertextBlob)
	captured.EncryptionContext = maps.Clone(input.EncryptionContext)
	f.decryptInput = &captured
	return f.decryptOut, f.decryptErr
}

func TestKMSAgentStateKeyWrapperRoundTripContract(t *testing.T) {
	fake := &fakeKMS{
		encryptOut: &kms.EncryptOutput{
			CiphertextBlob: []byte("kms-ciphertext"),
			KeyId:          aws.String(testKMSKeyARN),
		},
		decryptOut: &kms.DecryptOutput{
			KeyId:     aws.String(testKMSKeyARN),
			Plaintext: bytes.Repeat([]byte{0x42}, 32),
		},
	}
	wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(fake, "alias/qurl-proof")
	if err != nil {
		t.Fatal(err)
	}
	binding := qurl.AgentStateKeyBinding{
		Purpose:         "qurl-go/agent-state",
		EnvelopeVersion: 1,
		ProviderID:      "aws-kms",
		AgentID:         "agent-123",
	}
	dek := bytes.Repeat([]byte{0x24}, 32)
	wrapped, err := wrapper.WrapKey(t.Context(), dek, binding)
	if err != nil {
		t.Fatal(err)
	}
	wantContext := map[string]string{
		awsstore.KMSAgentStateContextPurpose:         binding.Purpose,
		awsstore.KMSAgentStateContextEnvelopeVersion: "1",
		awsstore.KMSAgentStateContextProviderID:      binding.ProviderID,
		awsstore.KMSAgentStateContextAgentID:         binding.AgentID,
	}
	if aws.ToString(fake.encryptInput.KeyId) != "alias/qurl-proof" ||
		fake.encryptInput.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecSymmetricDefault ||
		!maps.Equal(fake.encryptInput.EncryptionContext, wantContext) {
		t.Fatalf("Encrypt input = %#v", fake.encryptInput)
	}
	if !bytes.Equal(dek, bytes.Repeat([]byte{0x24}, 32)) {
		t.Fatal("WrapKey mutated caller-owned DEK")
	}
	if wrapped.Version != 1 || !bytes.Equal(wrapped.Ciphertext, []byte("kms-ciphertext")) ||
		string(wrapped.Metadata) != `{"key_id":"`+testKMSKeyARN+`"}` {
		t.Fatalf("wrapped key = %#v", wrapped)
	}

	plaintext, err := wrapper.UnwrapKey(t.Context(), wrapped, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatal("UnwrapKey returned the wrong DEK")
	}
	if aws.ToString(fake.decryptInput.KeyId) != testKMSKeyARN ||
		fake.decryptInput.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecSymmetricDefault ||
		!maps.Equal(fake.decryptInput.EncryptionContext, wantContext) ||
		!bytes.Equal(fake.decryptInput.CiphertextBlob, []byte("kms-ciphertext")) {
		t.Fatalf("Decrypt input = %#v", fake.decryptInput)
	}
}

func TestKMSAgentStateKeyWrapperRequiresConcreteKMSKeyARN(t *testing.T) {
	binding := qurl.AgentStateKeyBinding{
		Purpose:         "qurl-go/agent-state",
		EnvelopeVersion: 1,
		ProviderID:      "aws-kms",
		AgentID:         "agent-123",
	}
	for name, testCase := range map[string]struct {
		keyARN  string
		wantErr bool
	}{
		"uuid key": {
			keyARN: testKMSKeyARN,
		},
		"multi-region key": {
			keyARN: "arn:aws:kms:us-east-2:111122223333:key/mrk-0123456789abcdef0123456789abcdef",
		},
		"arbitrary key resource": {
			keyARN:  "arn:aws:kms:us-east-2:111122223333:key/not-a-real-key-id",
			wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeKMS{encryptOut: &kms.EncryptOutput{
				CiphertextBlob: []byte("kms-ciphertext"),
				KeyId:          aws.String(testCase.keyARN),
			}}
			wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(fake, "alias/qurl-proof")
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := wrapper.WrapKey(t.Context(), make([]byte, 32), binding)
			if testCase.wantErr {
				if err == nil {
					t.Fatal("WrapKey accepted a non-key KMS ARN")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(wrapped.Metadata) != `{"key_id":"`+testCase.keyARN+`"}` {
				t.Fatalf("metadata = %s", wrapped.Metadata)
			}
		})
	}
}

func TestKMSAgentStateKeyWrapperRejectsInvalidConfigurationAndBindingBeforeKMS(t *testing.T) {
	var nilFake *fakeKMS
	for name, testCase := range map[string]struct {
		client awsstore.KMSAPI
		keyID  string
	}{
		"nil client":       {client: nil, keyID: testKMSKeyARN},
		"typed nil client": {client: nilFake, keyID: testKMSKeyARN},
		"empty key":        {client: &fakeKMS{}, keyID: ""},
		"noncanonical key": {client: &fakeKMS{}, keyID: " alias/qurl "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := awsstore.NewKMSAgentStateKeyWrapper(testCase.client, testCase.keyID); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
				t.Fatalf("NewKMSAgentStateKeyWrapper = %v", err)
			}
		})
	}

	fake := &fakeKMS{}
	wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(fake, testKMSKeyARN)
	if err != nil {
		t.Fatal(err)
	}
	valid := qurl.AgentStateKeyBinding{Purpose: "qurl-go/agent-state", EnvelopeVersion: 1, ProviderID: "aws-kms", AgentID: "agent-123"}
	for name, mutate := range map[string]func(*qurl.AgentStateKeyBinding){
		"purpose":  func(binding *qurl.AgentStateKeyBinding) { binding.Purpose = "" },
		"version":  func(binding *qurl.AgentStateKeyBinding) { binding.EnvelopeVersion = 0 },
		"provider": func(binding *qurl.AgentStateKeyBinding) { binding.ProviderID = " aws-kms" },
		"agent":    func(binding *qurl.AgentStateKeyBinding) { binding.AgentID = "agent\n123" },
	} {
		t.Run(name, func(t *testing.T) {
			binding := valid
			mutate(&binding)
			if _, err := wrapper.WrapKey(t.Context(), make([]byte, 32), binding); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
				t.Fatalf("WrapKey = %v", err)
			}
			if fake.encryptInput != nil {
				t.Fatal("invalid binding reached KMS Encrypt")
			}
		})
	}
	if _, err := wrapper.WrapKey(t.Context(), make([]byte, 31), valid); !errors.Is(err, qurl.ErrInvalidBootstrapConfig) {
		t.Fatalf("short WrapKey = %v", err)
	}
}

func TestKMSAgentStateKeyWrapperFailsClosedOnInvalidWrappedRecords(t *testing.T) {
	validBinding := qurl.AgentStateKeyBinding{Purpose: "qurl-go/agent-state", EnvelopeVersion: 1, ProviderID: "aws-kms", AgentID: "agent-123"}
	validRecord := qurl.WrappedAgentStateKey{
		Ciphertext: []byte("kms-ciphertext"),
		Metadata:   []byte(`{"key_id":"` + testKMSKeyARN + `"}`),
	}
	for name, record := range map[string]qurl.WrappedAgentStateKey{
		"version":  {Version: 2, Ciphertext: validRecord.Ciphertext, Metadata: validRecord.Metadata},
		"empty":    {Version: 1, Metadata: validRecord.Metadata},
		"metadata": {Version: 1, Ciphertext: validRecord.Ciphertext, Metadata: []byte(`{"key_id":"alias/qurl"}`)},
		"fake key": {Version: 1, Ciphertext: validRecord.Ciphertext, Metadata: []byte(`{"key_id":"arn:aws:kms:us-east-2:111122223333:key/not-a-real-key-id"}`)},
		"unknown":  {Version: 1, Ciphertext: validRecord.Ciphertext, Metadata: []byte(`{"key_id":"` + testKMSKeyARN + `","extra":true}`)},
	} {
		t.Run(name, func(t *testing.T) {
			wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(&fakeKMS{}, testKMSKeyARN)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrapper.UnwrapKey(t.Context(), record, validBinding); !errors.Is(err, qurl.ErrInvalidWrappedAgentStateKey) {
				t.Fatalf("UnwrapKey = %v", err)
			}
		})
	}
}

func TestKMSAgentStateKeyWrapperClassifiesProviderFailures(t *testing.T) {
	binding := qurl.AgentStateKeyBinding{Purpose: "qurl-go/agent-state", EnvelopeVersion: 1, ProviderID: "aws-kms", AgentID: "agent-123"}
	record := qurl.WrappedAgentStateKey{
		Version:    1,
		Ciphertext: []byte("kms-ciphertext"),
		Metadata:   []byte(`{"key_id":"` + testKMSKeyARN + `"}`),
	}
	for name, providerErr := range map[string]error{
		"invalid ciphertext": &kmstypes.InvalidCiphertextException{},
		"incorrect key":      &kmstypes.IncorrectKeyException{},
	} {
		t.Run(name, func(t *testing.T) {
			wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(&fakeKMS{decryptErr: providerErr}, testKMSKeyARN)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrapper.UnwrapKey(t.Context(), record, binding); !errors.Is(err, qurl.ErrInvalidWrappedAgentStateKey) {
				t.Fatalf("UnwrapKey = %v", err)
			}
		})
	}

	operational := errors.New("KMS unavailable")
	wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(&fakeKMS{decryptErr: operational}, testKMSKeyARN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.UnwrapKey(t.Context(), record, binding); !errors.Is(err, operational) || errors.Is(err, qurl.ErrInvalidWrappedAgentStateKey) {
		t.Fatalf("operational UnwrapKey = %v", err)
	}
}

func TestKMSAgentStateKeyWrapperRejectsSuccessfulMismatchedDecrypt(t *testing.T) {
	binding := qurl.AgentStateKeyBinding{Purpose: "qurl-go/agent-state", EnvelopeVersion: 1, ProviderID: "aws-kms", AgentID: "agent-123"}
	record := qurl.WrappedAgentStateKey{
		Version:    1,
		Ciphertext: []byte("kms-ciphertext"),
		Metadata:   []byte(`{"key_id":"` + testKMSKeyARN + `"}`),
	}
	for name, output := range map[string]*kms.DecryptOutput{
		"wrong key":    {KeyId: aws.String("arn:aws:kms:us-east-2:111122223333:key/ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"), Plaintext: make([]byte, 32)},
		"wrong length": {KeyId: aws.String(testKMSKeyARN), Plaintext: make([]byte, 31)},
	} {
		t.Run(name, func(t *testing.T) {
			wrapper, err := awsstore.NewKMSAgentStateKeyWrapper(&fakeKMS{decryptOut: output}, testKMSKeyARN)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrapper.UnwrapKey(t.Context(), record, binding); !errors.Is(err, qurl.ErrInvalidWrappedAgentStateKey) {
				t.Fatalf("UnwrapKey = %v", err)
			}
			if !bytes.Equal(output.Plaintext, make([]byte, len(output.Plaintext))) {
				t.Fatal("rejected plaintext was not wiped")
			}
		})
	}
}
