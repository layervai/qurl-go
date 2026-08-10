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
	runAWS    func(context.Context, ...string) ([]byte, error)

	mu        sync.Mutex
	code      string
	fresh     bool
	callCount int
}

func newOTPMailbox(cfg otpE2EConfig) *otpMailbox {
	return &otpMailbox{
		queueURL:  cfg.mailboxQueueURL,
		bucket:    cfg.mailboxBucket,
		recipient: cfg.mailboxRecipient,
		region:    cfg.mailboxRegion,
		runAWS:    runAWSCLI,
	}
}

func runAWSCLI(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "aws", args...).Output()
	if err != nil {
		// Deliberately does not echo stderr: AWS errors can carry request
		// context, and this runs in a public repository's CI logs.
		return nil, errors.New("mailbox AWS operation failed")
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
		S3 struct {
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

// receive long-polls until a message addressed to this agent arrives, or ctx
// expires. Messages that are not ours are deleted and skipped so a stale one
// cannot wedge the queue for later runs.
func (m *otpMailbox) receive(ctx context.Context, agentID string) (string, error) {
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
		if err := ctx.Err(); err != nil {
			return "", errors.New("no OTP email arrived before the deadline")
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
		key, err := url.QueryUnescape(record.S3.Object.Key)
		if err != nil || record.S3.Bucket.Name != m.bucket || !strings.HasPrefix(key, "otp/") {
			return "", errors.New("mailbox notification escaped its expected bucket or prefix")
		}

		path := dir + "/message"
		if _, err := m.runAWS(ctx, "s3api", "get-object",
			"--bucket", m.bucket, "--key", key, path, "--region", m.region); err != nil {
			return "", err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("read fetched mailbox message")
		}
		_ = os.Remove(path)

		code, matched, err := extractOTPCode(body, m.recipient, agentID)
		if err != nil {
			return "", err
		}
		// Consume it either way: an unmatched message is not ours and must not
		// be left to wedge the queue for the next run.
		if _, err := m.runAWS(ctx, "s3api", "delete-object",
			"--bucket", m.bucket, "--key", key, "--region", m.region); err != nil {
			return "", err
		}
		if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
			return "", err
		}
		if matched {
			return code, nil
		}
	}
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
		return nil, fmt.Errorf("mailbox message uses an unsupported transfer encoding")
	}
}

// newBase64Reader decodes a base64 MIME part. Line breaks are stripped because
// base64 bodies are wrapped, and the standard decoder rejects them.
func newBase64Reader(body io.Reader) io.Reader {
	stripped := &newlineStrippingReader{inner: body}
	return base64.NewDecoder(base64.StdEncoding, stripped)
}

type newlineStrippingReader struct{ inner io.Reader }

func (r *newlineStrippingReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if n > 0 {
		filtered := p[:0]
		for _, b := range p[:n] {
			if b != '\r' && b != '\n' {
				filtered = append(filtered, b)
			}
		}
		n = len(filtered)
	}
	return n, err
}
