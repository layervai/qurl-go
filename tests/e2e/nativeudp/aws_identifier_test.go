package nativeudp_test

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// Shape validators for the AWS identifiers the sandbox proof consumes.
//
// This repository is public, so no proof resource may be named by a committed
// literal. The proof still has to fail closed on a malformed or mismatched
// prerequisite, so every identifier is checked twice: once for its own shape,
// and once for agreement with the other identifiers the same run was handed.
// The account number is the binding value -- it is read out of the
// operator-supplied queue URL and every other ARN must repeat it, which is what
// the committed constants used to prove, without naming the account.

// Fixture identifiers. These name nothing: the account is the one AWS reserves
// for its own documentation examples, and the recipient sits under the RFC 2606
// .test TLD, which can never resolve.
const (
	fixtureAWSAccount   = "123456789012"
	fixtureOTPMailbox   = "qurl-go-proof-otp-mailbox"
	fixtureOTPRecipient = "qurl-go@proof.example.test"
	fixtureKMSAlias     = "alias/qurl-go-proof-agent-seal"
	// RFC 5737 TEST-NET-3: reserved for documentation, never routable.
	fixtureProofSourceIP = "203.0.113.7"
)

var (
	awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-[1-9][0-9]?$`)

	// S3 names the bucket in the host position of a virtual-hosted URL, so the
	// DNS-compatible subset is the only one the proof can use.
	s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

	sqsQueueURLPattern = regexp.MustCompile(
		`^https://sqs\.([a-z0-9-]+)\.amazonaws\.com/([0-9]{12})/([A-Za-z0-9_-]{1,80})$`)

	kmsAliasPattern = regexp.MustCompile(`^alias/[A-Za-z0-9/_-]{1,250}$`)

	kmsKeyARNPattern = regexp.MustCompile(
		`^arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key/` +
			`(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

	// Qualified only -- by alias or by an immutable published version. An
	// unqualified ARN would let the proof mutate whichever version happened to
	// be published last, which is the one thing a release gate must not do; a
	// numeric version cannot move, so it satisfies the same property.
	lambdaAliasARNPattern = regexp.MustCompile(
		`^arn:aws:lambda:([a-z0-9-]+):([0-9]{12}):function:[A-Za-z0-9_-]{1,64}:([A-Za-z0-9_-]{1,128})$`)

	// One bare addr-spec. extractProofOTP matches this against the raw To:
	// header, so a display name or angle brackets would silently never match.
	proofRecipientPattern = regexp.MustCompile(
		"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*" +
			`@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
)

// isCustomerManagedKMSAlias reports whether value is a KMS alias the proof
// account owns. AWS-managed keys (alias/aws/...) are rejected: they cannot
// carry the key policy the sealed-state proof depends on.
func isCustomerManagedKMSAlias(value string) bool {
	return kmsAliasPattern.MatchString(value) && !strings.HasPrefix(value, "alias/aws/")
}

// parseSQSQueueURL returns the region, account, and queue name of a canonical
// SQS queue URL.
func parseSQSQueueURL(value string) (region, account, queue string, ok bool) {
	match := sqsQueueURLPattern.FindStringSubmatch(value)
	if match == nil {
		return "", "", "", false
	}
	return match[1], match[2], match[3], true
}

// isKMSKeyARNInAccount reports whether value is a well-formed KMS key ARN owned
// by account. Alias ARNs are rejected: the sealed envelope records the key that
// actually wrapped the data key, which AWS always reports as a key ARN.
func isKMSKeyARNInAccount(value, account string) bool {
	if account == "" {
		return false
	}
	match := kmsKeyARNPattern.FindStringSubmatch(value)
	return match != nil && match[2] == account
}

// isQualifiedLambdaARNInAccount reports whether value is a qualified Lambda ARN
// owned by account. The qualifier may be an alias or an immutable published
// version; what it may not be is absent or $LATEST, either of which would let
// the target move under the proof.
func isQualifiedLambdaARNInAccount(value, account string) bool {
	if account == "" {
		return false
	}
	match := lambdaAliasARNPattern.FindStringSubmatch(value)
	if match == nil || match[2] != account {
		return false
	}
	// "$LATEST" cannot reach this point through the character class, but a
	// bare "LATEST" alias would, and it reads as a version pin without being
	// one.
	return !strings.EqualFold(match[3], "LATEST")
}

// isProofBucketInAccount reports whether value is a well-formed S3 bucket name
// carrying the account-number suffix every sandbox proof bucket is created
// with. The suffix is what makes the name globally unique, so a bucket without
// it belongs to some other estate.
func isProofBucketInAccount(value, account string) bool {
	if account == "" {
		return false
	}
	return s3BucketPattern.MatchString(value) && strings.HasSuffix(value, "-"+account)
}

// cgnatIPv4Range is RFC 6598 shared address space. netip's IsPrivate does not
// cover it, but a carrier-assigned address is not a public egress either.
var cgnatIPv4Range = netip.MustParsePrefix("100.64.0.0/10")

// isPublicUnicastIPv4 reports whether value is a routable public IPv4 address.
// The proof runner's egress address is dispatch data, not a committed constant,
// but it still must be a real public source: a private, loopback, link-local,
// or multicast value means the capture was taken somewhere other than the
// internet-facing runner the evidence claims.
func isPublicUnicastIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.Zone() != "" {
		return false
	}
	if cgnatIPv4Range.Contains(address) {
		return false
	}
	return !address.IsPrivate() &&
		!address.IsLoopback() &&
		!address.IsLinkLocalUnicast() &&
		!address.IsLinkLocalMulticast() &&
		!address.IsMulticast() &&
		!address.IsUnspecified() &&
		!address.IsInterfaceLocalMulticast()
}

// The descriptor binding these helpers implement is only reachable from an
// attended live proof run, so it is proved here instead: the account agreement
// that replaced the committed literals has to be exercised by ordinary CI or it
// is not a gate at all.
func TestProofIdentifiersBindToOneAccount(t *testing.T) {
	const otherAccount = "111122223333"

	t.Run("bucket", func(t *testing.T) {
		for name, testCase := range map[string]struct {
			value   string
			account string
			want    bool
		}{
			"account-suffixed":   {value: "qurl-go-proof-handshake-" + fixtureAWSAccount, account: fixtureAWSAccount, want: true},
			"another account":    {value: "qurl-go-proof-handshake-" + otherAccount, account: fixtureAWSAccount},
			"no account suffix":  {value: "qurl-go-proof-handshake", account: fixtureAWSAccount},
			"account infix only": {value: "qurl-" + fixtureAWSAccount + "-proof", account: fixtureAWSAccount},
			"uppercase":          {value: "Qurl-Go-Proof-" + fixtureAWSAccount, account: fixtureAWSAccount},
			"empty account":      {value: "qurl-go-proof-handshake-" + fixtureAWSAccount, account: ""},
		} {
			t.Run(name, func(t *testing.T) {
				if got := isProofBucketInAccount(testCase.value, testCase.account); got != testCase.want {
					t.Fatalf("isProofBucketInAccount(%q, %q) = %t, want %t", testCase.value, testCase.account, got, testCase.want)
				}
			})
		}
	})

	t.Run("lambda qualifier", func(t *testing.T) {
		const base = "arn:aws:lambda:us-east-2:"
		for name, testCase := range map[string]struct {
			value   string
			account string
			want    bool
		}{
			"alias qualified":   {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm:blue", account: fixtureAWSAccount, want: true},
			"another alias":     {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm:green", account: fixtureAWSAccount, want: true},
			"another account":   {value: base + otherAccount + ":function:qurl-go-proof-ca-pm:blue", account: fixtureAWSAccount},
			"unqualified":       {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm", account: fixtureAWSAccount},
			"explicit latest":   {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm:$LATEST", account: fixtureAWSAccount},
			"bare latest":       {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm:LATEST", account: fixtureAWSAccount},
			"version qualifier": {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm:12", account: fixtureAWSAccount, want: true},
			"empty account":     {value: base + fixtureAWSAccount + ":function:qurl-go-proof-ca-pm:blue", account: ""},
		} {
			t.Run(name, func(t *testing.T) {
				if got := isQualifiedLambdaARNInAccount(testCase.value, testCase.account); got != testCase.want {
					t.Fatalf("isQualifiedLambdaARNInAccount(%q, %q) = %t, want %t", testCase.value, testCase.account, got, testCase.want)
				}
			})
		}
	})

	t.Run("queue url", func(t *testing.T) {
		region, account, queue, ok := parseSQSQueueURL(
			"https://sqs.us-east-2.amazonaws.com/" + fixtureAWSAccount + "/" + fixtureOTPMailbox)
		if !ok || region != "us-east-2" || account != fixtureAWSAccount || queue != fixtureOTPMailbox {
			t.Fatalf("parseSQSQueueURL = %q, %q, %q, %t", region, account, queue, ok)
		}
		for name, value := range map[string]string{
			"http":               "http://sqs.us-east-2.amazonaws.com/" + fixtureAWSAccount + "/" + fixtureOTPMailbox,
			"look-alike host":    "https://sqs.us-east-2.amazonaws.com.evil.test/" + fixtureAWSAccount + "/" + fixtureOTPMailbox,
			"short account":      "https://sqs.us-east-2.amazonaws.com/12345/" + fixtureOTPMailbox,
			"trailing path":      "https://sqs.us-east-2.amazonaws.com/" + fixtureAWSAccount + "/" + fixtureOTPMailbox + "/extra",
			"missing queue name": "https://sqs.us-east-2.amazonaws.com/" + fixtureAWSAccount + "/",
		} {
			t.Run(name, func(t *testing.T) {
				if _, _, _, ok := parseSQSQueueURL(value); ok {
					t.Fatalf("parseSQSQueueURL(%q) accepted a malformed queue URL", value)
				}
			})
		}
	})

	t.Run("kms alias", func(t *testing.T) {
		for name, testCase := range map[string]struct {
			value string
			want  bool
		}{
			"customer managed": {value: fixtureKMSAlias, want: true},
			"aws managed":      {value: "alias/aws/s3"},
			"bare key id":      {value: "01234567-89ab-cdef-0123-456789abcdef"},
			"key arn":          {value: "arn:aws:kms:us-east-2:" + fixtureAWSAccount + ":key/01234567-89ab-cdef-0123-456789abcdef"},
			"no alias prefix":  {value: "qurl-go-proof-agent-seal"},
		} {
			t.Run(name, func(t *testing.T) {
				if got := isCustomerManagedKMSAlias(testCase.value); got != testCase.want {
					t.Fatalf("isCustomerManagedKMSAlias(%q) = %t, want %t", testCase.value, got, testCase.want)
				}
			})
		}
	})
}

func TestPublicUnicastIPv4(t *testing.T) {
	for name, testCase := range map[string]struct {
		value string
		want  bool
	}{
		"public":         {value: "203.0.113.7", want: true},
		"private 10":     {value: "10.0.0.4"},
		"private 172":    {value: "172.16.5.9"},
		"private 192":    {value: "192.168.1.1"},
		"loopback":       {value: "127.0.0.1"},
		"link local":     {value: "169.254.169.254"},
		"cgnat":          {value: "100.64.1.1"},
		"multicast":      {value: "224.0.0.1"},
		"unspecified":    {value: "0.0.0.0"},
		"ipv6":           {value: "2001:db8::1"},
		"not an address": {value: "not-an-address"},
		"cidr":           {value: "203.0.113.0/24"},
		"empty":          {value: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isPublicUnicastIPv4(testCase.value); got != testCase.want {
				t.Fatalf("isPublicUnicastIPv4(%q) = %t, want %t", testCase.value, got, testCase.want)
			}
		})
	}
}

func TestRedactedAWSArguments(t *testing.T) {
	got := redactedAWSArguments([]string{
		"s3api", "put-object",
		"--region", "us-east-2",
		"--bucket", "qurl-go-proof-handshake-" + fixtureAWSAccount,
		"--key", "handshake/v1/123/1/abc/checkpoint.json",
		"--ssekms-key-id", "arn:aws:kms:us-east-2:" + fixtureAWSAccount + ":key/01234567-89ab-cdef-0123-456789abcdef",
		"--if-none-match", "*",
	})
	const want = "s3api put-object --region <redacted> --bucket <redacted> --key <redacted> " +
		"--ssekms-key-id <redacted> --if-none-match <redacted>"
	if got != want {
		t.Fatalf("redactedAWSArguments = %q, want %q", got, want)
	}
	// The point of the helper: no operand survives into a public log.
	for _, leaked := range []string{fixtureAWSAccount, "handshake/v1", "arn:aws:kms"} {
		if strings.Contains(got, leaked) {
			t.Errorf("redacted argv still carries %q", leaked)
		}
	}
}

// The forms redactedAWSArguments must not pass through: positional operands of
// a flagless subcommand, and the --flag=value spelling.
func TestRedactedAWSArgumentsCoversPositionalAndEqualsForms(t *testing.T) {
	positional := redactedAWSArguments([]string{
		"s3", "cp", "s3://qurl-go-proof-handshake-" + fixtureAWSAccount + "/checkpoint.json", "./local.json",
	})
	if positional != "s3 cp <redacted> <redacted>" {
		t.Fatalf("positional argv = %q", positional)
	}
	if strings.Contains(positional, fixtureAWSAccount) {
		t.Error("positional operand leaked the account")
	}
	equals := redactedAWSArguments([]string{
		"s3api", "put-object",
		"--bucket=qurl-go-proof-handshake-" + fixtureAWSAccount,
		"--region=us-east-2",
	})
	if equals != "s3api put-object --bucket=<redacted> --region=<redacted>" {
		t.Fatalf("equals-form argv = %q", equals)
	}
	if strings.Contains(equals, fixtureAWSAccount) {
		t.Error("--flag=value form leaked the account")
	}
}
