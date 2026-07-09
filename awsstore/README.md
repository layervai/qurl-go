# qurl-go/awsstore

**AWS-backed `qurl.AgentStateStore` implementations: persist a qURL agent
identity in AWS Secrets Manager or SSM Parameter Store instead of a local file.**

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go/awsstore.svg)](https://pkg.go.dev/github.com/layervai/qurl-go/awsstore)

`awsstore` is a **separate Go module** so the AWS SDK for Go v2 dependency lives
here and never leaks into the root `qurl` module. Programs that use the
file-backed store or a custom store pull in no AWS code.

```sh
go get github.com/layervai/qurl-go/awsstore@latest
```

## When to use which store

| Store | Backing | Reach for it when |
| --- | --- | --- |
| `SecretsManagerStore` | Secrets Manager `SecretString` | The agent identity is a first-class secret you want rotation hooks, resource policies, and CloudTrail **data events** on. |
| `ParameterStore` | SSM Parameter Store `SecureString` | You want a lighter-weight, lower-cost option that is still KMS-encrypted at rest. |
| `qurl.FileAgentState` (root module) | Local file, `0600` | Single host, or **shared storage via EFS** — see the EFS recipe below. |

> **The stored value is a credential.** A registered `AgentState` contains
> `DeviceAPIKey`, the bearer token the returned `Client` authorizes with. Encrypt
> it with a customer-managed KMS key (`WithKMSKeyID`), scope IAM to the single
> resource, and keep it out of logs.

## Secrets Manager

```go
import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

func newStore(ctx context.Context) (qurl.AgentStateStore, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := secretsmanager.NewFromConfig(cfg)
	return awsstore.NewSecretsManagerStore(
		client,
		"qurl/agent-state",                       // secret name or ARN
		awsstore.WithKMSKeyID("alias/qurl-agent"), // customer-managed CMK (recommended)
	), nil
}
```

Then hand the store to `qurl.RegisterAgent` (or `qurl.BootstrapAgent`) exactly as
you would `qurl.FileAgentState`:

```go
store, err := newStore(ctx)
// ...
client, err := qurl.RegisterAgent(ctx, setupKey, store)
```

- **Load**: `GetSecretValue` → JSON-unmarshal `SecretString`. A missing secret
  (`ResourceNotFoundException`) maps to `qurl.ErrAgentStateNotFound`; a present
  but undecodable value maps to `qurl.ErrInvalidAgentState`.
- **Save**: `PutSecretValue`; on first write (secret does not exist yet)
  `CreateSecret` with the configured KMS key, then idempotent thereafter.

> **KMS on Secrets Manager:** the customer-managed key is bound at
> **`CreateSecret`** time (`PutSecretValue` has no `KmsKeyId` field — the
> encryption key is a property of the secret). Set `WithKMSKeyID` before the first
> save, or precreate the secret with the desired key, to guarantee the credential
> is CMK-encrypted.

### IAM (least privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "QurlAgentSecret",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:CreateSecret"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:qurl/agent-state-*"
    },
    {
      "Sid": "QurlAgentSecretKMS",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/CMK_KEY_ID"
    }
  ]
}
```

Drop `secretsmanager:CreateSecret` if you precreate the secret out of band (e.g.
via Terraform) and only ever read/update it at runtime. The Secrets Manager ARN
carries a random 6-character suffix, hence the trailing `-*`.

## SSM Parameter Store

```go
import (
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/layervai/qurl-go/awsstore"
)

client := ssm.NewFromConfig(cfg)
store := awsstore.NewParameterStore(
	client,
	"/qurl/agent-state",                       // parameter name
	awsstore.WithKMSKeyID("alias/qurl-agent"), // customer-managed CMK (recommended)
)
```

- **Load**: `GetParameter` with `WithDecryption=true` → JSON-unmarshal `Value`. A
  missing parameter (`ParameterNotFound`) maps to `qurl.ErrAgentStateNotFound`; a
  present but undecodable value maps to `qurl.ErrInvalidAgentState`.
- **Save**: `PutParameter` with `Type=SecureString`, `Overwrite=true`. The
  configured KMS key (`KeyId`) is applied on **every** write, so switching keys
  takes effect on the next save.

### IAM (least privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "QurlAgentParameter",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:PutParameter"],
      "Resource": "arn:aws:ssm:REGION:ACCOUNT_ID:parameter/qurl/agent-state"
    },
    {
      "Sid": "QurlAgentParameterKMS",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/CMK_KEY_ID"
    }
  ]
}
```

The parameter ARN drops the leading slash of the name:
`/qurl/agent-state` → `parameter/qurl/agent-state`.

## EFS recipe (shared storage — no AWS store needed)

For EFS-backed or otherwise shared POSIX storage, **do not use these stores**.
Point the root module's file store at the mounted path:

```go
import "github.com/layervai/qurl-go/qurl"

store := qurl.FileAgentState("/mnt/efs/qurl/agent-state.json")
```

`FileAgentState` writes atomically (temp file + `rename`) with a `0600` file under
a `0700` directory, so an EFS mount shared across tasks gets the same
not-found → `ErrAgentStateNotFound`, corrupt → `ErrInvalidAgentState` contract
without pulling in the AWS SDK. Encrypt the EFS file system at rest with KMS and
restrict the access point's POSIX uid/gid to the agent. Run enrollment from **one
task at a time** for a given path: the write is atomic, but the SDK does not lock
across concurrent processes sharing the file.

## The implementor contract

Both stores honor the `qurl.AgentStateStore` contract that
`RegisterAgent`/`BootstrapAgent` rely on:

- `LoadAgentState` returns `qurl.ErrAgentStateNotFound` (via `errors.Is`) when no
  state exists yet → the caller starts a fresh enrollment.
- `LoadAgentState` returns a wrapped `qurl.ErrInvalidAgentState` (via `errors.Is`)
  when a value **is** present but cannot be decoded (corrupt / non-JSON).
- `SaveAgentState` persists the state so a later `LoadAgentState` returns an equal
  value.

Both sentinels are exported from the parent `qurl` package, so:

```go
if errors.Is(err, qurl.ErrAgentStateNotFound) { /* not registered yet */ }
if errors.Is(err, qurl.ErrInvalidAgentState) { /* corrupt stored state */ }
```

## Releasing

`awsstore` is a submodule that `require`s the parent `qurl` module. Tag in two
steps so the submodule's `require` resolves to a published parent tag:

1. Tag the **root** module first: `v0.1.0`.
2. Then tag the **submodule**: `awsstore/v0.1.0`.

During local development the parent is resolved from the in-tree copy via the
repo-root `go.work` (and the `replace github.com/layervai/qurl-go => ../` in
`awsstore/go.mod`), so no tag is required to build. A tagged release drops the
placeholder `require github.com/layervai/qurl-go v0.0.0` for the real root tag.
