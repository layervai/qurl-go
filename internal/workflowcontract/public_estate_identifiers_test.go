package workflowcontract

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// layervai/qurl-go is a PUBLIC repository, and so are this repository's
// workflow run logs. The sandbox proof reads its estate -- account, buckets,
// queues, keys, Secrets Manager paths -- from environment secrets and dispatch
// inputs, never from a committed literal, and the proof assertions check the
// shape of those values and their agreement with each other rather than
// pinning them.
//
// Nothing about that arrangement stops the next person from pasting a real
// identifier back into a fixture, so this is the gate that does. It matches on
// identifier SHAPE rather than on a denylist of specific values, because a
// denylist would have to name in this file exactly what it is trying to keep
// out of the repository.
//
// What this cannot catch: an internal resource NAME carries no distinguishing
// shape -- a bucket or function name is just a hyphenated string, and no
// regexp separates one estate's from another's. The defence against that is
// architectural rather than lexical: the workflow contract test requires every
// estate value to be wired from `secrets.*`, so there is no committed field
// for a name to be pasted into in the first place.
//
// (Note for whoever edits this file next: do not illustrate that paragraph
// with a real name. An example here is a committed literal like any other --
// that mistake was made once already while writing this file.)
type estatePattern struct {
	name string
	// pattern must expose the account number as its first capture group when
	// accountBearing is true.
	pattern        *regexp.Regexp
	accountBearing bool
	// exclude, when set, drops any match that OVERLAPS one of its matches.
	// RE2 has no lookaround, so a shape cheaper to subtract than to encode is
	// subtracted here. Overlap rather than equality matters: a pattern can
	// match a fragment of the thing being excluded rather than the whole of
	// it.
	exclude *regexp.Regexp
}

// A UUID's final group is twelve characters wide, so a UUID whose last group
// happens to be all digits has the same tail shape as a bucket name carrying an
// account suffix. This repository commits UUIDs as KMS key-id fixtures, so that
// collision is real and has to be subtracted rather than tolerated.
//
// (Deliberately described rather than illustrated: an example here would be a
// committed literal, and TestScannerScansItself would -- correctly -- fail on
// it. That happened while writing this comment.)
var uuidPattern = regexp.MustCompile(
	`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

var estatePatterns = []estatePattern{
	{
		name:           "AWS account number in an ARN",
		pattern:        regexp.MustCompile(`arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):`),
		accountBearing: true,
	},
	{
		name:           "AWS account number in an SQS queue URL",
		pattern:        regexp.MustCompile(`sqs\.[a-z0-9-]+\.amazonaws\.com/([0-9]{12})/`),
		accountBearing: true,
	},
	{
		name:           "AWS account number in an ECR registry host",
		pattern:        regexp.MustCompile(`([0-9]{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com`),
		accountBearing: true,
	},
	{
		// EC2-style resource ids are always an 8- or 17-character hex suffix,
		// which is specific enough not to collide with prose or with the
		// 40-character commit SHAs this repository pins everywhere.
		name: "AWS resource id",
		pattern: regexp.MustCompile(
			`\b(?:sg|vpc|subnet|eni|vol|rtb|acl|igw|nat|eipalloc|ami|i)-(?:[0-9a-f]{8}|[0-9a-f]{17})\b`),
	},
	{
		name:    "AWS long-term access key id",
		pattern: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		// Every sandbox proof bucket carries the account as its name suffix --
		// that is what isProofBucketInAccount binds against -- so it is the one
		// account-bearing form with no ARN or URL around it to key on. The
		// trailing delimiter keeps a workflow run id embedded mid-token (
		// "nhp-<runid>-1-qurl_go-...") from matching: there the digits are
		// followed by more identifier, not by the end of a value.
		name: "AWS account number as a resource-name suffix",
		pattern: regexp.MustCompile(
			"(?m)\\b[a-z0-9][a-z0-9-]{2,60}-([0-9]{12})(?:[\"'`\\s,;)\\]}]|$)"),
		accountBearing: true,
		exclude:        uuidPattern,
	},
}

// Accounts that name nothing: AWS reserves these for its own documentation and
// this repository reuses them as fixtures.
var documentationAWSAccounts = map[string]bool{
	"123456789012": true,
	"111122223333": true,
	"000000000000": true,
}

func TestRepositoryCommitsNoAWSEstateIdentifiers(t *testing.T) {
	root := repositoryRoot(t)
	var findings []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Git objects carry the history this change deliberately does not
			// rewrite, and vendored trees are not ours to police.
			switch entry.Name() {
			case ".git", "vendor", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return nil //nolint:nilerr // an unreadable or oversized blob is not a source literal
		}
		contents, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(contents, 0) >= 0 {
			return nil //nolint:nilerr // binary
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			relative = path
		}
		// This file is deliberately NOT excluded. It states its patterns as
		// regexp source, which none of them match, so it can scan itself --
		// and it must, because an exclusion is exactly how a real value gets
		// pasted into the one file nothing checks. TestScannerScansItself
		// pins that property.
		for _, class := range estatePatterns {
			var excluded [][]int
			if class.exclude != nil {
				excluded = class.exclude.FindAllIndex(contents, -1)
			}
			for _, span := range class.pattern.FindAllSubmatchIndex(contents, -1) {
				if class.accountBearing && span[2] >= 0 &&
					documentationAWSAccounts[string(contents[span[2]:span[3]])] {
					continue
				}
				if overlapsAny(span[0], span[1], excluded) {
					continue
				}
				findings = append(findings,
					class.name+" at "+relative+":"+lineAt(contents, span[0]))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if len(findings) != 0 {
		// The matched text is never echoed: this failure is read in a public
		// CI log, and reproducing the value here would leak precisely what the
		// test exists to keep out.
		t.Fatalf(
			"a real AWS estate identifier is committed to this public repository in %d place(s):\n  %s\n"+
				"read the value from an environment secret and assert its shape instead; see "+
				"tests/e2e/nativeudp/aws_identifier_test.go",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// overlapsAny reports whether [start, end) intersects any of the spans.
func overlapsAny(start, end int, spans [][]int) bool {
	for _, span := range spans {
		if start < span[1] && span[0] < end {
			return true
		}
	}
	return false
}

// lineAt reports the 1-indexed line of an offset. The matched text is never
// reproduced -- this failure is read in a public CI log.
func lineAt(contents []byte, offset int) string {
	return strconv.Itoa(bytes.Count(contents[:offset], []byte("\n")) + 1)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	return filepath.Join(filepath.Dir(testFile), "..", "..")
}

// TestScannerScansItself guards the self-exclusion that used to be here: if a
// future pattern starts matching this file's own regexp source, the natural fix
// is to rewrite the pattern, not to skip the file.
func TestScannerScansItself(t *testing.T) {
	root := repositoryRoot(t)
	self := filepath.Join(root, "internal", "workflowcontract", "public_estate_identifiers_test.go")
	contents, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	for _, class := range estatePatterns {
		if class.pattern.Match(contents) {
			t.Errorf("%s matches this file's own source; rewrite the pattern rather than excluding the file", class.name)
		}
	}
}
