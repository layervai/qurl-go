module github.com/layervai/qurl-go/awsstore

go 1.26.5

// Keeping awsstore a SEPARATE module is deliberate: it isolates the AWS SDK v2
// dependency here so the root qurl module stays AWS-SDK-free.
require (
	github.com/aws/aws-sdk-go-v2 v1.43.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.73.0
	github.com/aws/smithy-go v1.27.5 // indirect
	github.com/layervai/qurl-go v0.0.0
)

require (
	github.com/aws/aws-sdk-go-v2/config v1.32.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.1
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.32 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.32 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.2 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// The parent qurl module is required at the placeholder v0.0.0 and resolved from
// the in-tree parent via this replace, so awsstore builds against the local
// parent (both standalone and under the repo-root go.work). This is the same
// in-repo submodule pattern the AWS SDK itself uses for its service modules. A
// tagged release drops the placeholder for the published root tag — see the
// README "Releasing" section (root v0.1.0, then awsstore/v0.1.0).
replace github.com/layervai/qurl-go => ../
