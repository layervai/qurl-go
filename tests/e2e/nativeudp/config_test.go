package nativeudp_test

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

const (
	strictEnv                = "QURL_GO_SANDBOX_STRICT"
	buildSHAEnv              = "QURL_GO_SANDBOX_EXPECTED_SHA"
	hubHostEnv               = "QURL_GO_SANDBOX_HUB_HOST"
	hubPortEnv               = "QURL_GO_SANDBOX_HUB_PORT"
	hubServerKeyEnv          = "QURL_GO_SANDBOX_HUB_SERVER_PUBLIC_KEY_B64"
	enrollmentEnv            = "QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL"
	agentIDEnv               = "QURL_GO_SANDBOX_AGENT_ID"
	statePathEnv             = "QURL_GO_SANDBOX_STATE_PATH"
	provenancePathEnv        = "QURL_GO_SANDBOX_PROVENANCE_PATH"
	deploymentManifestSHAEnv = "QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"
	typedContractSHAEnv      = "QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"
	candidateKindEnv         = "QURL_GO_SANDBOX_CANDIDATE_KIND"
	candidatePathEnv         = "QURL_GO_SANDBOX_CANDIDATE_PATH"
	candidateCommitPathEnv   = "QURL_GO_SANDBOX_CANDIDATE_COMMIT_PATH"
	knockResourceIDEnv       = "QURL_GO_SANDBOX_KNOCK_RESOURCE_ID"
	expectedCellIDEnv        = "QURL_GO_SANDBOX_EXPECTED_CELL_ID"
	assignmentHandshakeEnv   = "QURL_GO_SANDBOX_ASSIGNMENT_HANDSHAKE_B64"
	controllerRunIDEnv       = "QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID"
	controllerRunAttemptEnv  = "QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT"
	clientRunIDEnv           = "QURL_GO_SANDBOX_CLIENT_RUN_ID"
	otpMailboxQueueURLEnv    = "QURL_GO_SANDBOX_OTP_MAILBOX_QUEUE_URL"
	otpMailboxBucketEnv      = "QURL_GO_SANDBOX_OTP_MAILBOX_BUCKET"
	otpMailboxRecipientEnv   = "QURL_GO_SANDBOX_OTP_MAILBOX_RECIPIENT"
	otpMailboxRegionEnv      = "QURL_GO_SANDBOX_OTP_MAILBOX_REGION"
	proofSourceIPEnv         = "QURL_GO_SANDBOX_PROOF_SOURCE_IP"
	standardNHPUDPPort       = 443
	x25519PublicKeyLength    = 32
)

type sandboxConfig struct {
	buildSHA             string
	hubHost              string
	hubPort              int
	hubServerKeyB64      string
	enrollment           string
	agentID              string
	statePath            string
	provenancePath       string
	deploymentSHA        string
	typedContractSHA     string
	candidateKind        string
	candidatePath        string
	candidateCommit      string
	knockResourceID      string
	expectedCellID       string
	kmsKeyID             string
	assignmentHandshake  string
	controllerRunID      string
	controllerRunAttempt string
	clientRunID          string
	otpQueueURL          string
	otpBucket            string
	otpRecipient         string
	otpRegion            string
	// awsAccount is read out of the operator-supplied queue URL rather than
	// committed. Every other proof ARN must repeat it.
	awsAccount string
	// proofSourceIP is the runner egress address the transport capture must
	// show. It is configured rather than committed, so the transport
	// descriptor can be compared against it instead of merely shape-checked.
	proofSourceIP string
}

func loadSandboxConfig(lookup func(string) string) (sandboxConfig, bool, error) {
	strict := lookup(strictEnv)
	switch strict {
	case "", "0", "false":
		return sandboxConfig{}, false, nil
	case "1", "true":
	default:
		return sandboxConfig{}, false, fmt.Errorf("%s must be true/1 or false/0", strictEnv)
	}

	required := []string{
		buildSHAEnv,
		hubHostEnv,
		hubPortEnv,
		hubServerKeyEnv,
		enrollmentEnv,
		agentIDEnv,
		statePathEnv,
		provenancePathEnv,
		deploymentManifestSHAEnv,
		typedContractSHAEnv,
		candidateKindEnv,
		candidatePathEnv,
		candidateCommitPathEnv,
		knockResourceIDEnv,
		sandboxKMSKeyIDEnv,
		assignmentHandshakeEnv,
		controllerRunIDEnv,
		controllerRunAttemptEnv,
		clientRunIDEnv,
		otpMailboxQueueURLEnv,
		otpMailboxBucketEnv,
		otpMailboxRecipientEnv,
		otpMailboxRegionEnv,
		proofSourceIPEnv,
	}
	missing := make([]string, 0, len(required))
	for _, name := range required {
		if lookup(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return sandboxConfig{}, true, fmt.Errorf("strict native UDP sandbox proof is missing required environment: %s", strings.Join(missing, ", "))
	}

	port, err := strconv.Atoi(lookup(hubPortEnv))
	if err != nil || port != standardNHPUDPPort {
		return sandboxConfig{}, true, fmt.Errorf("%s must be the native NHP UDP port %d", hubPortEnv, standardNHPUDPPort)
	}
	cfg := sandboxConfig{
		buildSHA:             lookup(buildSHAEnv),
		hubHost:              lookup(hubHostEnv),
		hubPort:              port,
		hubServerKeyB64:      lookup(hubServerKeyEnv),
		enrollment:           lookup(enrollmentEnv),
		agentID:              lookup(agentIDEnv),
		statePath:            lookup(statePathEnv),
		provenancePath:       lookup(provenancePathEnv),
		deploymentSHA:        lookup(deploymentManifestSHAEnv),
		typedContractSHA:     lookup(typedContractSHAEnv),
		candidateKind:        lookup(candidateKindEnv),
		candidatePath:        lookup(candidatePathEnv),
		candidateCommit:      lookup(candidateCommitPathEnv),
		knockResourceID:      lookup(knockResourceIDEnv),
		expectedCellID:       lookup(expectedCellIDEnv),
		kmsKeyID:             lookup(sandboxKMSKeyIDEnv),
		assignmentHandshake:  lookup(assignmentHandshakeEnv),
		controllerRunID:      lookup(controllerRunIDEnv),
		controllerRunAttempt: lookup(controllerRunAttemptEnv),
		clientRunID:          lookup(clientRunIDEnv),
		otpQueueURL:          lookup(otpMailboxQueueURLEnv),
		otpBucket:            lookup(otpMailboxBucketEnv),
		otpRecipient:         lookup(otpMailboxRecipientEnv),
		otpRegion:            lookup(otpMailboxRegionEnv),
		proofSourceIP:        lookup(proofSourceIPEnv),
	}

	if !canonicalLowerHex(cfg.buildSHA, 40) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an exact 40-character lowercase Git SHA", buildSHAEnv)
	}
	for name, value := range map[string]string{
		hubHostEnv:               cfg.hubHost,
		hubServerKeyEnv:          cfg.hubServerKeyB64,
		enrollmentEnv:            cfg.enrollment,
		agentIDEnv:               cfg.agentID,
		statePathEnv:             cfg.statePath,
		provenancePathEnv:        cfg.provenancePath,
		deploymentManifestSHAEnv: cfg.deploymentSHA,
		typedContractSHAEnv:      cfg.typedContractSHA,
		candidateKindEnv:         cfg.candidateKind,
		candidatePathEnv:         cfg.candidatePath,
		candidateCommitPathEnv:   cfg.candidateCommit,
		knockResourceIDEnv:       cfg.knockResourceID,
		expectedCellIDEnv:        cfg.expectedCellID,
		sandboxKMSKeyIDEnv:       cfg.kmsKeyID,
		assignmentHandshakeEnv:   cfg.assignmentHandshake,
		controllerRunIDEnv:       cfg.controllerRunID,
		controllerRunAttemptEnv:  cfg.controllerRunAttempt,
		clientRunIDEnv:           cfg.clientRunID,
		otpMailboxQueueURLEnv:    cfg.otpQueueURL,
		otpMailboxBucketEnv:      cfg.otpBucket,
		otpMailboxRecipientEnv:   cfg.otpRecipient,
		otpMailboxRegionEnv:      cfg.otpRegion,
		proofSourceIPEnv:         cfg.proofSourceIP,
	} {
		if value != strings.TrimSpace(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return sandboxConfig{}, true, fmt.Errorf("%s must be canonical and contain no control characters", name)
		}
	}
	if len(cfg.enrollment) < 32 {
		return sandboxConfig{}, true, fmt.Errorf("%s must contain a server-minted credential of at least 32 bytes", enrollmentEnv)
	}
	if !assignmentRunRE.MatchString(cfg.clientRunID) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be a positive workflow run ID", clientRunIDEnv)
	}
	// The proof resources are not named by committed literals -- this
	// repository is public. Each identifier is instead checked for its own
	// shape and for agreement with the others this run was handed, so a
	// malformed, mismatched, or foreign-estate prerequisite still fails here
	// rather than reaching a proof that would act on it.
	if !isCustomerManagedKMSAlias(cfg.kmsKeyID) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be a customer-managed KMS alias, not a bare key id, ARN, or AWS-managed key", sandboxKMSKeyIDEnv)
	}
	if !awsRegionPattern.MatchString(cfg.otpRegion) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be a well-formed AWS region", otpMailboxRegionEnv)
	}
	if !s3BucketPattern.MatchString(cfg.otpBucket) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be a well-formed private proof mailbox bucket name", otpMailboxBucketEnv)
	}
	if !proofRecipientPattern.MatchString(cfg.otpRecipient) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be one bare addr-spec with no display name or angle brackets", otpMailboxRecipientEnv)
	}
	queueRegion, queueAccount, queueName, ok := parseSQSQueueURL(cfg.otpQueueURL)
	if !ok {
		return sandboxConfig{}, true, fmt.Errorf("%s must be a well-formed SQS queue URL", otpMailboxQueueURLEnv)
	}
	if queueRegion != cfg.otpRegion {
		return sandboxConfig{}, true, fmt.Errorf("%s must name a queue in %s=%s", otpMailboxQueueURLEnv, otpMailboxRegionEnv, cfg.otpRegion)
	}
	// The queue is the delivery notification for the bucket, so the two must
	// be the same mailbox. Two separately valid identifiers that name
	// different mailboxes would wait forever for an OTP that landed elsewhere.
	if queueName != cfg.otpBucket {
		return sandboxConfig{}, true, fmt.Errorf("%s and %s must name the same proof mailbox", otpMailboxQueueURLEnv, otpMailboxBucketEnv)
	}
	cfg.awsAccount = queueAccount
	if !isPublicUnicastIPv4(cfg.proofSourceIP) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be the runner's public unicast IPv4 egress address", proofSourceIPEnv)
	}
	if err := validateSandboxAgentID(cfg.agentID); err != nil {
		return sandboxConfig{}, true, fmt.Errorf("%s: %w", agentIDEnv, err)
	}
	if !filepath.IsAbs(cfg.statePath) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an absolute path", statePathEnv)
	}
	if !filepath.IsAbs(cfg.provenancePath) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an absolute path", provenancePathEnv)
	}
	// Only the two exact candidate shapes the workflow can resolve. An unknown
	// or absent kind fails here rather than reaching a proof that would have to
	// guess which authenticated document it is holding.
	if cfg.candidateKind != candidateKindOpenPullRequest && cfg.candidateKind != candidateKindMainContained {
		return sandboxConfig{}, true, fmt.Errorf("%s must be %s or %s", candidateKindEnv, candidateKindOpenPullRequest, candidateKindMainContained)
	}
	if !filepath.IsAbs(cfg.candidatePath) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an absolute path", candidatePathEnv)
	}
	if !filepath.IsAbs(cfg.candidateCommit) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an absolute path", candidateCommitPathEnv)
	}
	if filepath.Clean(cfg.candidatePath) == filepath.Clean(cfg.candidateCommit) {
		return sandboxConfig{}, true, fmt.Errorf("%s and %s must resolve to distinct paths", candidatePathEnv, candidateCommitPathEnv)
	}
	if !canonicalLowerHex(cfg.deploymentSHA, 64) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an exact lowercase SHA-256 digest", deploymentManifestSHAEnv)
	}
	if !canonicalLowerHex(cfg.typedContractSHA, 64) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an exact lowercase SHA-256 digest", typedContractSHAEnv)
	}
	paths := []struct {
		name string
		path string
	}{
		{name: statePathEnv, path: filepath.Clean(cfg.statePath)},
		{name: statePathEnv + " lock", path: filepath.Clean(cfg.statePath + ".lock")},
		{name: provenancePathEnv, path: filepath.Clean(cfg.provenancePath)},
		{name: provenancePathEnv + " temporary", path: filepath.Clean(cfg.provenancePath + ".tmp")},
	}
	seenPaths := make(map[string]string, len(paths))
	for _, candidate := range paths {
		if prior, exists := seenPaths[candidate.path]; exists {
			return sandboxConfig{}, true, fmt.Errorf("%s and %s must resolve to distinct paths", prior, candidate.name)
		}
		seenPaths[candidate.path] = candidate.name
	}
	serverKey, err := base64.StdEncoding.Strict().DecodeString(cfg.hubServerKeyB64)
	if err != nil || len(serverKey) != x25519PublicKeyLength || base64.StdEncoding.EncodeToString(serverKey) != cfg.hubServerKeyB64 {
		return sandboxConfig{}, true, fmt.Errorf("%s must be canonical padded base64 for one 32-byte X25519 public key", hubServerKeyEnv)
	}
	return cfg, true, nil
}

func canonicalLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range len(value) {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func validateSandboxAgentID(agentID string) error {
	if len(agentID) < 2 || len(agentID) > 64 {
		return fmt.Errorf("agent id must contain 2-64 characters")
	}
	for i := range len(agentID) {
		b := agentID[i]
		lowerAlnum := b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
		if !lowerAlnum && (b != '-' || i == 0 || i == len(agentID)-1) {
			return fmt.Errorf("agent id must start and end with lowercase alphanumeric characters and contain only lowercase alphanumeric characters or hyphens")
		}
	}
	return nil
}

func TestSandboxConfigStrictMode(t *testing.T) {
	valid := map[string]string{
		strictEnv:                "true",
		buildSHAEnv:              strings.Repeat("a", 40),
		hubHostEnv:               "hub.nhp.layerv.ai",
		hubPortEnv:               strconv.Itoa(standardNHPUDPPort),
		hubServerKeyEnv:          base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		enrollmentEnv:            strings.Repeat("credential", 4),
		agentIDEnv:               "qurl-go-sandbox-123-1",
		statePathEnv:             filepath.Join(t.TempDir(), "agent-state.json"),
		provenancePathEnv:        filepath.Join(t.TempDir(), "provenance.json"),
		deploymentManifestSHAEnv: strings.Repeat("d", 64),
		typedContractSHAEnv:      strings.Repeat("e", 64),
		candidateKindEnv:         candidateKindMainContained,
		candidatePathEnv:         filepath.Join(t.TempDir(), "qurl-go-candidate.json"),
		candidateCommitPathEnv:   filepath.Join(t.TempDir(), "qurl-go-candidate-commit.json"),
		knockResourceIDEnv:       "knock-resource-id",
		sandboxKMSKeyIDEnv:       fixtureKMSAlias,
		assignmentHandshakeEnv:   base64.StdEncoding.EncodeToString([]byte(`{"arm":{"result":{"agent_id":"qurl-go-sandbox-123-1","grant_correlation_id":"nhp-123-1-qurl_go-pre_removal-0123456789abcdef0123456789abcdef","lease_seconds":2100,"mutated_at":"2026-07-28T20:00:00Z","mutation":"arm","pinned_cell_id":"cell0","target_cell_id":"cell1"},"version":1},"descriptor":{"agent_id":"qurl-go-sandbox-123-1","arm_request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucket":"qurl-go-proof-handshake-` + fixtureAWSAccount + `","ca_pm_alias_arn":"arn:aws:lambda:us-east-2:` + fixtureAWSAccount + `:function:qurl-go-proof-ca-pm:blue","channel_id":"0123456789abcdef0123456789abcdef","checkpoint_key":"handshake/v1/123/1/0123456789abcdef0123456789abcdef/checkpoint.json","client":"qurl_go","controller_run_attempt":"1","controller_run_id":"123","correlation_id":"nhp-123-1-qurl_go-pre_removal-0123456789abcdef0123456789abcdef","expire_request_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","kms_key_arn":"arn:aws:kms:us-east-2:` + fixtureAWSAccount + `:key/01234567-89ab-cdef-0123-456789abcdef","arm_lease_seconds":2100,"expire_lease_seconds":30,"move_request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pinned_cell_id":"cell0","proof_phase":"pre_removal","receipt_key":"handshake/v1/123/1/0123456789abcdef0123456789abcdef/receipt.json","target_cell_id":"cell1","version":1}}`)),
		controllerRunIDEnv:       "123",
		controllerRunAttemptEnv:  "1",
		clientRunIDEnv:           "456",
		otpMailboxQueueURLEnv:    "https://sqs.us-east-2.amazonaws.com/" + fixtureAWSAccount + "/" + fixtureOTPMailbox,
		otpMailboxBucketEnv:      fixtureOTPMailbox,
		otpMailboxRecipientEnv:   fixtureOTPRecipient,
		otpMailboxRegionEnv:      "us-east-2",
		proofSourceIPEnv:         fixtureProofSourceIP,
	}
	lookup := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}

	t.Run("disabled is an explicit skip", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(func(string) string { return "" })
		if enabled || err != nil || cfg != (sandboxConfig{}) {
			t.Fatalf("disabled config = %#v, %t, %v; want zero, false, nil", cfg, enabled, err)
		}
	})

	t.Run("strict accepts complete inputs", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(valid))
		if !enabled || err != nil || cfg.agentID != valid[agentIDEnv] {
			t.Fatalf("strict config = %#v, %t, %v", cfg, enabled, err)
		}
	})

	for _, kind := range []string{candidateKindOpenPullRequest, candidateKindMainContained} {
		t.Run("strict accepts candidate kind "+kind, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			values[candidateKindEnv] = kind
			cfg, enabled, err := loadSandboxConfig(lookup(values))
			if !enabled || err != nil || cfg.candidateKind != kind {
				t.Fatalf("candidate kind config = %#v, %t, %v", cfg, enabled, err)
			}
		})
	}

	for _, kind := range []string{"pull_request", "MAIN_CONTAINED", "any", "open_pull_request "} {
		t.Run("strict rejects candidate kind "+strconv.Quote(kind), func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			values[candidateKindEnv] = kind
			cfg, enabled, err := loadSandboxConfig(lookup(values))
			if !enabled || err == nil || cfg != (sandboxConfig{}) || !strings.Contains(err.Error(), candidateKindEnv) {
				t.Fatalf("unknown candidate kind config = %#v, %t, %v", cfg, enabled, err)
			}
		})
	}

	for _, name := range []string{deploymentManifestSHAEnv, typedContractSHAEnv} {
		t.Run("strict rejects noncanonical "+name, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			values[name] = strings.Repeat("A", 64)
			cfg, enabled, err := loadSandboxConfig(lookup(values))
			if !enabled || err == nil || cfg != (sandboxConfig{}) || !strings.Contains(err.Error(), name) {
				t.Fatalf("noncanonical digest config = %#v, %t, %v", cfg, enabled, err)
			}
		})
	}

	// The proof resources are no longer pinned by committed literals, so these
	// cases carry what the literals used to: a malformed identifier, or a
	// well-formed one that disagrees with the rest of the run's inputs, must
	// still fail closed here.
	t.Run("strict rejects malformed AWS prerequisites", func(t *testing.T) {
		queueURL := func(account, queue string) string {
			return "https://sqs.us-east-2.amazonaws.com/" + account + "/" + queue
		}
		for name, tt := range map[string]struct {
			overrides map[string]string
			wantEnv   string
		}{
			"kms bare key id": {
				overrides: map[string]string{sandboxKMSKeyIDEnv: "01234567-89ab-cdef-0123-456789abcdef"},
				wantEnv:   sandboxKMSKeyIDEnv,
			},
			"kms key arn instead of alias": {
				overrides: map[string]string{sandboxKMSKeyIDEnv: "arn:aws:kms:us-east-2:" + fixtureAWSAccount + ":key/01234567-89ab-cdef-0123-456789abcdef"},
				wantEnv:   sandboxKMSKeyIDEnv,
			},
			"aws-managed kms alias": {
				overrides: map[string]string{sandboxKMSKeyIDEnv: "alias/aws/s3"},
				wantEnv:   sandboxKMSKeyIDEnv,
			},
			"region is not a region": {
				overrides: map[string]string{otpMailboxRegionEnv: "US-EAST-2"},
				wantEnv:   otpMailboxRegionEnv,
			},
			"bucket carries uppercase": {
				overrides: map[string]string{otpMailboxBucketEnv: "Qurl-Go-Proof-Otp-Mailbox"},
				wantEnv:   otpMailboxBucketEnv,
			},
			"bucket carries an underscore": {
				overrides: map[string]string{otpMailboxBucketEnv: "qurl_go_proof_otp_mailbox"},
				wantEnv:   otpMailboxBucketEnv,
			},
			"recipient carries a display name": {
				overrides: map[string]string{otpMailboxRecipientEnv: "qURL <" + fixtureOTPRecipient + ">"},
				wantEnv:   otpMailboxRecipientEnv,
			},
			"recipient is not an address": {
				overrides: map[string]string{otpMailboxRecipientEnv: "qurl-go-proof-mailbox"},
				wantEnv:   otpMailboxRecipientEnv,
			},
			"queue url is not an sqs url": {
				overrides: map[string]string{otpMailboxQueueURLEnv: "https://example.test/" + fixtureOTPMailbox},
				wantEnv:   otpMailboxQueueURLEnv,
			},
			"queue url account is not an account": {
				overrides: map[string]string{otpMailboxQueueURLEnv: queueURL("12345", fixtureOTPMailbox)},
				wantEnv:   otpMailboxQueueURLEnv,
			},
			"queue url region contradicts the region": {
				overrides: map[string]string{
					otpMailboxQueueURLEnv: "https://sqs.eu-west-1.amazonaws.com/" + fixtureAWSAccount + "/" + fixtureOTPMailbox,
				},
				wantEnv: otpMailboxQueueURLEnv,
			},
			"proof source is a private address": {
				overrides: map[string]string{proofSourceIPEnv: "10.0.0.4"},
				wantEnv:   proofSourceIPEnv,
			},
			"proof source is not an address": {
				overrides: map[string]string{proofSourceIPEnv: "not-an-address"},
				wantEnv:   proofSourceIPEnv,
			},
			"queue names a different mailbox than the bucket": {
				overrides: map[string]string{otpMailboxQueueURLEnv: queueURL(fixtureAWSAccount, "some-other-mailbox")},
				wantEnv:   otpMailboxQueueURLEnv,
			},
		} {
			t.Run(name, func(t *testing.T) {
				values := make(map[string]string, len(valid))
				for key, value := range valid {
					values[key] = value
				}
				for key, value := range tt.overrides {
					values[key] = value
				}
				cfg, enabled, err := loadSandboxConfig(lookup(values))
				if !enabled || err == nil || cfg != (sandboxConfig{}) || !strings.Contains(err.Error(), tt.wantEnv) {
					t.Fatalf("malformed prerequisite config = %#v, %t, %v; want enabled failure naming %s", cfg, enabled, err, tt.wantEnv)
				}
			})
		}
	})

	// The account is derived, not committed, so the derivation itself is the
	// thing under test: everything downstream binds against it.
	t.Run("strict derives the proof account from the queue url", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(valid))
		if !enabled || err != nil {
			t.Fatalf("strict config = %#v, %t, %v", cfg, enabled, err)
		}
		if cfg.awsAccount != fixtureAWSAccount {
			t.Fatalf("derived proof account = %q, want %q", cfg.awsAccount, fixtureAWSAccount)
		}
	})

	t.Run("strict reports every missing prerequisite", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(map[string]string{strictEnv: "1"}))
		if !enabled || err == nil || cfg != (sandboxConfig{}) {
			t.Fatalf("missing config = %#v, %t, %v; want enabled failure", cfg, enabled, err)
		}
		for _, name := range []string{buildSHAEnv, hubHostEnv, hubPortEnv, hubServerKeyEnv, enrollmentEnv, agentIDEnv, statePathEnv, provenancePathEnv, deploymentManifestSHAEnv, typedContractSHAEnv, candidateKindEnv, candidatePathEnv, candidateCommitPathEnv, knockResourceIDEnv, sandboxKMSKeyIDEnv, assignmentHandshakeEnv, controllerRunIDEnv, controllerRunAttemptEnv, clientRunIDEnv, proofSourceIPEnv} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("missing-config error %q omits %s", err, name)
			}
		}
	})

	t.Run("invalid strict marker fails instead of disabling proof", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(map[string]string{strictEnv: "TRUE"}))
		if enabled || err == nil || cfg != (sandboxConfig{}) {
			t.Fatalf("invalid strict marker = %#v, %t, %v; want disabled-shape error", cfg, enabled, err)
		}
	})

	t.Run("strict rejects state and provenance path collisions", func(t *testing.T) {
		base := t.TempDir()
		tests := []struct {
			name       string
			state      string
			provenance string
		}{
			{
				name:       "same path",
				state:      filepath.Join(base, "shared.json"),
				provenance: filepath.Join(base, "shared.json"),
			},
			{
				name:       "provenance aliases state lock",
				state:      filepath.Join(base, "agent-state.json"),
				provenance: filepath.Join(base, "agent-state.json.lock"),
			},
			{
				name:       "state aliases provenance temporary",
				state:      filepath.Join(base, "provenance.json.tmp"),
				provenance: filepath.Join(base, "provenance.json"),
			},
			{
				name:       "cleaned paths alias",
				state:      filepath.Join(base, "agent-state.json"),
				provenance: filepath.Join(base, "nested", "..", "agent-state.json"),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				values := make(map[string]string, len(valid))
				for name, value := range valid {
					values[name] = value
				}
				values[statePathEnv] = tt.state
				values[provenancePathEnv] = tt.provenance
				cfg, enabled, err := loadSandboxConfig(lookup(values))
				if !enabled || err == nil || cfg != (sandboxConfig{}) || !strings.Contains(err.Error(), "must resolve to distinct paths") {
					t.Fatalf("colliding config = %#v, %t, %v; want enabled distinct-path failure", cfg, enabled, err)
				}
			})
		}
	})
}
