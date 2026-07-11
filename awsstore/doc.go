// Package awsstore provides AWS-backed [qurl.AgentStateStore] implementations for
// persisting a qURL agent identity in a managed AWS service instead of a local
// file.
//
// # Why a separate module
//
// awsstore is its own Go module (github.com/layervai/qurl-go/awsstore) so that
// the AWS SDK for Go v2 dependency lives here and never leaks into the root qurl
// module. Programs that use the file-backed store or a custom store pull in no
// AWS code.
//
// # Stores
//
//   - [SecretsManagerStore] persists the state as the SecretString of an AWS
//     Secrets Manager secret. Best when the agent identity is a first-class
//     secret you want rotation hooks, resource policies, and CloudTrail data
//     events on.
//   - [ParameterStore] persists the state as an AWS Systems Manager (SSM)
//     Parameter Store SecureString. A lighter-weight, lower-cost option that is
//     still KMS-encrypted at rest.
//
// For EFS-backed or otherwise shared POSIX storage, do NOT use these stores: use
// the root [qurl.FileAgentState] against the mounted path. See the package
// README for the EFS recipe.
//
// # The stored value is a credential
//
// A registered [qurl.AgentState] contains DeviceAPIKey, the bearer credential the
// returned Client authorizes with. Treat every value written by these stores as
// SECRET:
//
//   - Encrypt with a customer-managed KMS key via [WithKMSKeyID] rather than the
//     AWS-managed default key, so key access is auditable and revocable.
//   - Grant least-privilege IAM scoped to the single resource: for
//     [SecretsManagerStore], secretsmanager:GetSecretValue, PutSecretValue, and
//     CreateSecret on the one secret ARN (plus kms:Decrypt/GenerateDataKey on the
//     CMK); for [ParameterStore], ssm:GetParameter and ssm:PutParameter on the one
//     parameter ARN (plus the same KMS actions). The README has copy-pasteable
//     policy snippets.
//   - Keep it out of logs and crash dumps.
//
// # Implementor contract
//
// Both stores honor the [qurl.AgentStateStore] implementor contract that
// RegisterAgent/BootstrapAgent rely on:
//
//   - LoadAgentState returns [qurl.ErrAgentStateNotFound] (matchable with
//     errors.Is) when no state has been persisted yet, so the caller starts a
//     fresh enrollment instead of failing.
//   - LoadAgentState returns [qurl.ErrInvalidAgentState] (wrapped, matchable with
//     errors.Is) when a value IS present but cannot be decoded — a corrupt or
//     non-JSON blob — distinct from the not-found case.
//   - SaveAgentState writes the state so a subsequent LoadAgentState returns an
//     equal value.
package awsstore
