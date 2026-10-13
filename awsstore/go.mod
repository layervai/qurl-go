module github.com/layervai/qurl-go/awsstore

go 1.26.9

// Keeping awsstore a SEPARATE module is deliberate: it isolates the AWS SDK v2
// dependency here so the root qurl module stays AWS-SDK-free.
//
// The parent qurl module is required at its PUBLISHED root tag, with no
// `replace => ../`. That combination is what makes an external
// `go get github.com/layervai/qurl-go/awsstore@<tag>` resolve; the
// awsstore-release-guard workflow fails any awsstore/v* tag that reintroduces
// the old placeholder v0.0.0 require or a local-path parent replace.
//
// In-tree builds are unaffected: the repo-root go.work lists both modules, and
// a workspace overrides this require, so PR CI still vets and tests awsstore
// against the WORKING-TREE parent rather than the published tag. Only a
// GOWORK=off build (or an external consumer) resolves the tag below.
//
// Bump this in lockstep with each root release — see the README "Releasing"
// section: root vX.Y.Z first, then awsstore/vX.Y.Z.
require (
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.4
	github.com/aws/aws-sdk-go-v2/service/ssm v1.79.3
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/layervai/qurl-go v0.5.3
)

require (
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.4
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4 // indirect
	github.com/layervai/qurl-conformance v0.17.2 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
