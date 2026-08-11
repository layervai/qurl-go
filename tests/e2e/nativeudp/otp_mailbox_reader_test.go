package nativeudp_test

// Self-contained reader for the CI OTP mailbox.
//
// This deliberately depends on nothing from the attended native-UDP proof,
// which #168 retired: that suite's harness carried evidence collection,
// provenance, and a controller contract this gate has no use for, and taking a
// dependency on it is what made the previous version of this test break the
// moment the proof was deleted.
//
// It shells out to the `aws` CLI rather than importing aws-sdk-go-v2. The root
// module has exactly two direct requires and `awsstore` is a separate module
// precisely to keep AWS out of the public SDK's dependency graph; a test-only
// import would still land in it.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

// otpEmailSubject is the exact subject qurl-service stamps on the agent OTP
// email (internal/email: agentOTPSubject). A message with any other subject is
// not ours and is skipped rather than parsed.
const otpEmailSubject = "qURL Connector verification code"

// otpCodePattern matches the code line in the text/plain part. Anchoring on the
// surrounding copy rather than "any 8 digits" keeps an unrelated number
// elsewhere in the body from being mistaken for the code.
var otpCodePattern = regexp.MustCompile(`Your qURL Connector verification code is:\s*([0-9]{8})\b`)

// maxMailBytes bounds a decoded MIME part. A hostile or malformed message must
// not be able to exhaust the runner.
const maxMailBytes = 256 * 1024

type otpMailbox struct {
	queueURL  string
	bucket    string
	recipient string
	region    string
	// notBefore discards notifications for mail that arrived before this run
	// began. S3 stamps each record with an eventTime, so staleness is decided
	// on the delivery itself rather than on queue hygiene.
	notBefore time.Time
	// waitBudget is deliberately SHORTER than the caller's registration
	// deadline. The SDK discards this reader's error and returns the bare
	// ctx.Err() whenever the outer context is already done, so a mailbox
	// timeout that races the outer deadline surfaces as an opaque
	// "context deadline exceeded". Finishing first keeps the diagnosis.
	waitBudget time.Duration
	runAWS     func(context.Context, ...string) ([]byte, error)

	mu        sync.Mutex
	code      string
	fresh     bool
	callCount int
}

func newOTPMailbox(cfg otpE2EConfig, notBefore time.Time, waitBudget time.Duration) *otpMailbox {
	return &otpMailbox{
		queueURL:   cfg.mailboxQueueURL,
		bucket:     cfg.mailboxBucket,
		recipient:  cfg.mailboxRecipient,
		region:     cfg.mailboxRegion,
		notBefore:  notBefore,
		waitBudget: waitBudget,
		runAWS:     runAWSCLI,
	}
}

func runAWSCLI(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "aws", args...).Output()
	if err != nil {
		// Names the operation but not the AWS stderr, which can carry request
		// context and identifiers this public repository's CI logs should not
		// hold. Suppressing everything made a permissions failure read as a
		// generic outage and cost a diagnosis cycle; the verb is the part that
		// actually localises the fault.
		operation := "aws"
		if len(args) >= 2 {
			operation = args[0] + " " + args[1]
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("mailbox AWS operation %q failed (exit %d)", operation, exitErr.ExitCode())
		}
		return nil, fmt.Errorf("mailbox AWS operation %q failed", operation)
	}
	return out, nil
}

type sqsReceiveOutput struct {
	Messages []struct {
		ReceiptHandle string `json:"ReceiptHandle"`
		Body          string `json:"Body"`
	} `json:"Messages"`
}

type s3Notification struct {
	Event   string `json:"Event"`
	Records []struct {
		EventTime string `json:"eventTime"`
		S3        struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"s3"`
	} `json:"Records"`
}

// provide is the qurl.WithAgentRuntimeOTPProvider callback.
//
// A PendingActivationRecovery challenge replays the ORIGINAL code: that path
// exists precisely because the same enrollment is being resumed, and minting a
// second code would defeat it. A second FRESH challenge is an error, which is
// what makes the idempotency assertion in the test meaningful -- if a replay
// tried to enroll again it fails loudly here instead of quietly consuming
// another real email.
func (m *otpMailbox) provide(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
	if challenge.AgentID == "" || challenge.CellID == "" {
		return "", errors.New("OTP challenge is missing its agent or cell identity")
	}

	m.mu.Lock()
	m.callCount++
	if challenge.PendingActivationRecovery {
		code := m.code
		m.mu.Unlock()
		if code == "" {
			return "", errors.New("activation recovery requested before any code was delivered")
		}
		return code, nil
	}
	if m.fresh {
		m.mu.Unlock()
		return "", errors.New("a second fresh OTP challenge was issued; registration was not idempotent")
	}
	m.mu.Unlock()

	code, err := m.receive(ctx, challenge.AgentID)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.code, m.fresh = code, true
	m.mu.Unlock()
	return code, nil
}

func (m *otpMailbox) snapshot() (calls int, fresh bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount, m.fresh
}

// timedOut explains a mailbox wait that produced nothing.
//
// Registration OTP issuance is rate limited per credential (5/hour) and per
// owner (10/hour) in qurl-service. Once that budget is spent the authority
// refuses to issue and NO email is ever sent, which from here is
// indistinguishable from a delivery problem -- so name it rather than let the
// reader look broken. Re-running the gate while debugging is the fastest way
// to reach it.
func (m *otpMailbox) timedOut() error {
	return errors.New(
		"no OTP email arrived for this run. The likely cause is that no email was ever " +
			"sent: issuance is rate limited at 5/hour per credential and 10/hour per " +
			"owner, and while the credential pool spreads runs across owners to stay " +
			"under both, enough runs within the hour will still exhaust the slot this " +
			"run drew. Check the ca-iro-cell* log group for an Outcome other than " +
			"success before suspecting delivery")
}

// receive long-polls until a message addressed to this agent arrives, or ctx
// expires. A message that is not ours is deleted only when it predates this run
// -- anything newer is released back, because a concurrent run is still waiting
// for it.
func (m *otpMailbox) receive(ctx context.Context, agentID string) (string, error) {
	if m.waitBudget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.waitBudget)
		defer cancel()
	}
	dir, err := os.MkdirTemp("", "qurl-otp-mailbox-")
	if err != nil {
		return "", errors.New("create mailbox scratch directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", errors.New("secure mailbox scratch directory")
	}
	defer os.RemoveAll(dir)

	for {
		if ctx.Err() != nil {
			return "", m.timedOut()
		}
		raw, err := m.runAWS(ctx,
			"sqs", "receive-message",
			"--queue-url", m.queueURL,
			"--max-number-of-messages", "1",
			"--wait-time-seconds", "10",
			"--visibility-timeout", "60",
			"--region", m.region,
			"--output", "json",
		)
		if err != nil {
			// exec.CommandContext kills the CLI when the budget expires, which
			// surfaces as a generic non-zero exit. That is a timeout, and
			// reporting it as an AWS failure sent me hunting through IAM once
			// already.
			if ctx.Err() != nil {
				return "", m.timedOut()
			}
			return "", err
		}
		var received sqsReceiveOutput
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &received); err != nil {
				return "", errors.New("mailbox queue returned malformed JSON")
			}
		}
		if len(received.Messages) == 0 {
			continue
		}
		message := received.Messages[0]
		if message.ReceiptHandle == "" {
			return "", errors.New("mailbox queue returned a message with no receipt handle")
		}

		var notification s3Notification
		if err := json.Unmarshal([]byte(message.Body), &notification); err != nil {
			return "", errors.New("mailbox queue returned a malformed S3 notification")
		}
		// S3 emits one of these when the notification configuration is created.
		if notification.Event == "s3:TestEvent" {
			if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
				return "", err
			}
			continue
		}
		if len(notification.Records) != 1 {
			return "", errors.New("mailbox notification did not describe exactly one object")
		}
		record := notification.Records[0]
		// Deliveries from before this run started are nobody's: every run that
		// wanted them has finished. Delete those.
		//
		// Anything NEWER is potentially a concurrent run's, because the queue,
		// bucket, and recipient come from shared repo secrets and the workflow's
		// concurrency group only serialises the same ref. Releasing rather than
		// deleting is what actually upholds "concurrent runs cannot consume one
		// another's messages" -- the agent-id binding alone only stops a run
		// READING a foreign code, not destroying it.
		//
		// An unparseable eventTime is treated as not-stale and released, so a
		// malformed timestamp can never cause a delete.
		delivered, err := time.Parse(time.RFC3339, record.EventTime)
		if err == nil && delivered.Before(m.notBefore) {
			if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
				return "", err
			}
			continue
		}
		key, err := url.QueryUnescape(record.S3.Object.Key)
		if err != nil || record.S3.Bucket.Name != m.bucket || !strings.HasPrefix(key, "otp/") {
			return "", errors.New("mailbox notification escaped its expected bucket or prefix")
		}

		path := dir + "/message"
		if _, err := m.runAWS(ctx, "s3api", "get-object",
			"--bucket", m.bucket, "--key", key, path, "--region", m.region); err != nil {
			return "", err
		}
		body, err := readBoundedFile(path)
		if err != nil {
			return "", err
		}
		_ = os.Remove(path)

		code, matched, err := extractOTPCode(body, m.recipient, agentID)
		if err != nil {
			return "", err
		}
		if matched {
			// Ours: consume it. The S3 object is deliberately left alone -- the
			// gate role is read-only on the bucket and the mailbox expires
			// objects after a day, so asking for s3:DeleteObject would widen the
			// role for no benefit.
			if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
				return "", err
			}
			return code, nil
		}
		// Not ours, and recent enough to belong to a concurrent run. Release it
		// so its owner can still receive it, rather than deleting it and turning
		// their run red. The short delay keeps this loop from immediately
		// re-receiving the same message and spinning on it.
		if err := m.releaseMessage(ctx, message.ReceiptHandle); err != nil {
			return "", err
		}
	}
}

// releaseMessage returns a message to the queue for another run to receive.
func (m *otpMailbox) releaseMessage(ctx context.Context, receiptHandle string) error {
	_, err := m.runAWS(ctx,
		"sqs", "change-message-visibility",
		"--queue-url", m.queueURL,
		"--receipt-handle", receiptHandle,
		"--visibility-timeout", "10",
		"--region", m.region,
	)
	return err
}

func (m *otpMailbox) deleteMessage(ctx context.Context, dir, receiptHandle string) error {
	// Passed via --cli-input-json: a receipt handle can contain characters that
	// are awkward on a command line.
	path := dir + "/delete.json"
	payload, err := json.Marshal(map[string]string{"QueueUrl": m.queueURL, "ReceiptHandle": receiptHandle})
	if err != nil {
		return errors.New("encode mailbox delete request")
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return errors.New("write mailbox delete request")
	}
	_, err = m.runAWS(ctx, "sqs", "delete-message", "--cli-input-json", "file://"+path, "--region", m.region)
	_ = os.Remove(path)
	return err
}

// extractOTPCode returns the code if raw is the OTP email for this recipient
// and agent. matched=false means "not our message", which is not an error --
// only a malformed or ambiguous message is.
func extractOTPCode(raw []byte, recipient, agentID string) (code string, matched bool, err error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", false, errors.New("mailbox message is not valid RFC 5322 mail")
	}
	subject, err := (&mime.WordDecoder{}).DecodeHeader(message.Header.Get("Subject"))
	if err != nil {
		return "", false, errors.New("mailbox message subject is malformed")
	}
	if subject != otpEmailSubject {
		return "", false, nil
	}
	recipients, err := message.Header.AddressList("To")
	if err != nil {
		return "", false, errors.New("mailbox message recipient header is malformed")
	}
	if len(recipients) != 1 || !strings.EqualFold(recipients[0].Address, recipient) {
		return "", false, nil
	}
	body, err := decodeMIMEBody(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return "", false, err
	}
	// Binds the code to THIS agent, so concurrent gate runs cannot consume one
	// another's messages.
	if !strings.Contains(body, `Connector ID:  "`+agentID+`"`) {
		return "", false, nil
	}
	unique := make(map[string]struct{})
	for _, match := range otpCodePattern.FindAllStringSubmatch(body, -1) {
		unique[match[1]] = struct{}{}
	}
	if len(unique) != 1 {
		return "", false, errors.New("mailbox message did not contain exactly one distinct 8-digit code")
	}
	for candidate := range unique {
		return candidate, true, nil
	}
	return "", false, errors.New("mailbox code extraction failed")
}

func decodeMIMEBody(header textproto.MIMEHeader, body io.Reader) (string, error) {
	decoded, err := decodeTransferEncoding(header.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return "", err
	}
	contentType := header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil && contentType != "" {
		return "", errors.New("mailbox message content type is malformed")
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		raw, err := io.ReadAll(io.LimitReader(decoded, maxMailBytes+1))
		if err != nil || len(raw) > maxMailBytes {
			return "", errors.New("mailbox message body exceeded its bound")
		}
		return string(raw), nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", errors.New("multipart mailbox message has no boundary")
	}
	// Concatenate every part: the code lives in text/plain, and scanning all of
	// them avoids depending on part ordering.
	var combined strings.Builder
	reader := multipart.NewReader(decoded, boundary)
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("mailbox message multipart structure is malformed")
		}
		text, err := decodeMIMEBody(part.Header, part)
		_ = part.Close()
		if err != nil {
			return "", err
		}
		combined.WriteString(text)
		combined.WriteString("\n")
		if combined.Len() > maxMailBytes {
			return "", errors.New("mailbox message body exceeded its bound")
		}
	}
	return combined.String(), nil
}

func decodeTransferEncoding(encoding string, body io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		return body, nil
	case "quoted-printable":
		return quotedprintable.NewReader(body), nil
	case "base64":
		return newBase64Reader(body), nil
	default:
		return nil, errors.New("mailbox message uses an unsupported transfer encoding")
	}
}

// newBase64Reader decodes a base64 MIME part. Line breaks are stripped because
// base64 bodies are wrapped, and the standard decoder rejects them.
func newBase64Reader(body io.Reader) io.Reader {
	stripped := &newlineStrippingReader{inner: body}
	return base64.NewDecoder(base64.StdEncoding, stripped)
}

type newlineStrippingReader struct{ inner io.Reader }

// Read never returns (0, nil), including when the inner reader does. The
// discouraged zero-count/nil-error pair only happens to be safe here because
// base64.NewDecoder reads through io.ReadFull, and depending on a consumer's
// implementation detail is not a property worth keeping. Loop instead.
func (r *newlineStrippingReader) Read(p []byte) (int, error) {
	for {
		n, err := r.inner.Read(p)
		if n > 0 {
			filtered := p[:0]
			for _, b := range p[:n] {
				if b != '\r' && b != '\n' {
					filtered = append(filtered, b)
				}
			}
			if len(filtered) > 0 {
				return len(filtered), err
			}
			if err == nil {
				continue // stripped everything; go back for real bytes
			}
			return 0, err
		}
		if err == nil {
			continue // inner reader returned (0, nil); do not propagate it
		}
		return 0, err
	}
}

// readBoundedFile reads a fetched message under maxMailBytes.
//
// The cap previously bound only the decoded MIME part, so an oversized object
// was buffered whole before decoding ever ran -- the guarantee the maxMailBytes
// comment states was not actually enforced at the fetch. Low impact given the
// source is our own SES pipeline, but the bound should be where the claim is.
func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open fetched mailbox message")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxMailBytes+1))
	if err != nil {
		return nil, errors.New("read fetched mailbox message")
	}
	if len(body) > maxMailBytes {
		return nil, errors.New("fetched mailbox message exceeded its size bound")
	}
	return body, nil
}
