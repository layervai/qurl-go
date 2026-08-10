package nativeudp_test

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
	"testing"

	"github.com/layervai/qurl-go/qurl"
)

const (
	proofAccountKeyID    = "key_UdpProofOtp1"
	proofOTPEmailSubject = "qURL Connector verification code"
)

var proofOTPCodePattern = regexp.MustCompile(`Your qURL Connector verification code is:\s*([0-9]{8})\b`)

type sandboxOTPMailbox struct {
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

func newSandboxOTPMailbox(cfg sandboxConfig) *sandboxOTPMailbox {
	return &sandboxOTPMailbox{
		queueURL: cfg.otpQueueURL, bucket: cfg.otpBucket,
		recipient: cfg.otpRecipient, region: cfg.otpRegion,
		runAWS: runSandboxAWSCLI,
	}
}

func runSandboxAWSCLI(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "aws", args...)
	output, err := command.Output()
	if err != nil {
		return nil, errors.New("private proof mailbox AWS operation failed")
	}
	return output, nil
}

func (m *sandboxOTPMailbox) provide(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
	if challenge.AgentID == "" || challenge.CredentialKeyID != proofAccountKeyID || challenge.CellID == "" {
		return "", errors.New("private proof mailbox received an invalid OTP challenge")
	}

	m.mu.Lock()
	m.callCount++
	if challenge.PendingActivationRecovery {
		code := m.code
		m.mu.Unlock()
		if code == "" {
			return "", errors.New("private proof mailbox has no original code for activation recovery")
		}
		return code, nil
	}
	if m.fresh {
		m.mu.Unlock()
		return "", errors.New("private proof mailbox received a second fresh OTP challenge")
	}
	m.mu.Unlock()

	code, err := m.receive(ctx, challenge.AgentID)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.code = code
	m.fresh = true
	m.mu.Unlock()
	return code, nil
}

func (m *sandboxOTPMailbox) snapshot() (calls int, fresh bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount, m.fresh
}

func (m *sandboxOTPMailbox) receive(ctx context.Context, agentID string) (string, error) {
	tempDir, err := os.MkdirTemp("", "qurl-go-proof-otp-")
	if err != nil {
		return "", errors.New("create private proof mailbox directory")
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", errors.New("secure private proof mailbox directory")
	}
	defer os.RemoveAll(tempDir)

	for {
		if err := ctx.Err(); err != nil {
			return "", errors.New("private proof mailbox deadline elapsed")
		}
		raw, err := m.runAWS(ctx,
			"sqs", "receive-message",
			"--queue-url", m.queueURL,
			"--max-number-of-messages", "1",
			"--wait-time-seconds", "10",
			"--visibility-timeout", "60",
			"--region", m.region,
			"--query", "{Messages: Messages[].{ReceiptHandle:ReceiptHandle,Body:Body}}",
			"--output", "json",
		)
		if err != nil {
			return "", err
		}
		var received sqsReceiveOutput
		if err := strictJSON(raw, &received); err != nil {
			return "", errors.New("private proof mailbox returned malformed queue output")
		}
		if len(received.Messages) == 0 {
			continue
		}
		if len(received.Messages) != 1 || received.Messages[0].ReceiptHandle == "" {
			return "", errors.New("private proof mailbox returned an invalid message batch")
		}
		message := received.Messages[0]

		var notification s3Notification
		if err := json.Unmarshal([]byte(message.Body), &notification); err != nil {
			return "", errors.New("private proof mailbox returned a malformed S3 notification")
		}
		if notification.Event == "s3:TestEvent" {
			if err := m.deleteQueueMessage(ctx, tempDir, message.ReceiptHandle); err != nil {
				return "", err
			}
			continue
		}
		if len(notification.Records) != 1 {
			return "", errors.New("private proof mailbox notification must contain exactly one object")
		}
		record := notification.Records[0]
		key, err := url.QueryUnescape(record.S3.Object.Key)
		if err != nil || record.S3.Bucket.Name != m.bucket || !strings.HasPrefix(key, "otp/") {
			return "", errors.New("private proof mailbox notification escaped its exact bucket or prefix")
		}

		messagePath := tempDir + "/message"
		file, err := os.OpenFile(messagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return "", errors.New("create private proof mailbox message file")
		}
		if err := file.Close(); err != nil {
			return "", errors.New("close private proof mailbox message file")
		}
		if _, err := m.runAWS(ctx,
			"s3api", "get-object",
			"--bucket", m.bucket,
			"--key", key,
			messagePath,
			"--region", m.region,
		); err != nil {
			return "", err
		}
		messageRaw, err := os.ReadFile(messagePath)
		if err != nil {
			return "", errors.New("read private proof mailbox message")
		}
		_ = os.Remove(messagePath)

		code, matches, err := extractProofOTP(messageRaw, m.recipient, agentID)
		if err != nil {
			return "", err
		}
		if _, err := m.runAWS(ctx,
			"s3api", "delete-object",
			"--bucket", m.bucket,
			"--key", key,
			"--region", m.region,
		); err != nil {
			return "", err
		}
		if err := m.deleteQueueMessage(ctx, tempDir, message.ReceiptHandle); err != nil {
			return "", err
		}
		if matches {
			return code, nil
		}
	}
}

func (m *sandboxOTPMailbox) deleteQueueMessage(ctx context.Context, tempDir, receiptHandle string) error {
	inputPath := tempDir + "/delete-message.json"
	input, err := os.OpenFile(inputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("create private proof mailbox cleanup input")
	}
	encoder := json.NewEncoder(input)
	if err := encoder.Encode(map[string]string{"QueueUrl": m.queueURL, "ReceiptHandle": receiptHandle}); err != nil {
		_ = input.Close()
		return errors.New("encode private proof mailbox cleanup input")
	}
	if err := input.Close(); err != nil {
		return errors.New("close private proof mailbox cleanup input")
	}
	_, err = m.runAWS(ctx,
		"sqs", "delete-message",
		"--cli-input-json", "file://"+inputPath,
		"--region", m.region,
	)
	_ = os.Remove(inputPath)
	return err
}

func extractProofOTP(raw []byte, recipient, agentID string) (code string, matches bool, err error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", false, errors.New("private proof mailbox message is not valid RFC 5322 mail")
	}
	subject, err := (&mime.WordDecoder{}).DecodeHeader(message.Header.Get("Subject"))
	if err != nil {
		return "", false, errors.New("private proof mailbox subject is malformed")
	}
	if subject != proofOTPEmailSubject {
		return "", false, nil
	}
	recipients, err := message.Header.AddressList("To")
	if err != nil {
		return "", false, errors.New("private proof mailbox recipient header is malformed")
	}
	if len(recipients) != 1 || !strings.EqualFold(recipients[0].Address, recipient) {
		return "", false, nil
	}
	body, err := decodeMIMEBody(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return "", false, err
	}
	if !strings.Contains(body, `Connector ID:  "`+agentID+`"`) {
		return "", false, nil
	}
	unique := make(map[string]struct{})
	for _, match := range proofOTPCodePattern.FindAllStringSubmatch(body, -1) {
		unique[match[1]] = struct{}{}
	}
	if len(unique) != 1 {
		return "", false, errors.New("private proof mailbox message did not contain one unique 8-digit code")
	}
	for candidate := range unique {
		return candidate, true, nil
	}
	return "", false, errors.New("private proof mailbox code extraction failed")
}

func decodeMIMEBody(header textproto.MIMEHeader, body io.Reader) (string, error) {
	decoded, err := decodeTransferEncoding(header.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return "", err
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil && header.Get("Content-Type") != "" {
		return "", errors.New("private proof mailbox MIME content type is malformed")
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		raw, err := io.ReadAll(io.LimitReader(decoded, 256*1024+1))
		if err != nil || len(raw) > 256*1024 {
			return "", errors.New("private proof mailbox MIME body exceeded its bound")
		}
		return string(raw), nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", errors.New("private proof mailbox multipart boundary is missing")
	}
	reader := multipart.NewReader(decoded, boundary)
	var combined strings.Builder
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("private proof mailbox multipart body is malformed")
		}
		partBody, err := decodeMIMEBody(part.Header, part)
		_ = part.Close()
		if err != nil {
			return "", err
		}
		if combined.Len()+len(partBody) > 256*1024 {
			return "", errors.New("private proof mailbox MIME body exceeded its bound")
		}
		combined.WriteString(partBody)
		combined.WriteByte('\n')
	}
	return combined.String(), nil
}

func decodeTransferEncoding(encoding string, body io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		return body, nil
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body), nil
	case "quoted-printable":
		return quotedprintable.NewReader(body), nil
	default:
		return nil, fmt.Errorf("private proof mailbox used unsupported transfer encoding")
	}
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func TestExtractProofOTP(t *testing.T) {
	raw := []byte("To: " + fixtureOTPRecipient + "\r\n" +
		"Subject: qURL Connector verification code\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		"Your qURL Connector verification code is: 12345678\r\n" +
		"Connector ID:  \"qurl-go-sandbox-123-1\"\r\n")
	code, matches, err := extractProofOTP(raw, fixtureOTPRecipient, "qurl-go-sandbox-123-1")
	if err != nil || !matches || code != "12345678" {
		t.Fatalf("extract valid proof OTP = %q, %t, %v", code, matches, err)
	}

	for name, changed := range map[string][]byte{
		"wrong agent":     bytes.ReplaceAll(raw, []byte("qurl-go-sandbox-123-1"), []byte("qurl-go-sandbox-other")),
		"wrong recipient": bytes.ReplaceAll(raw, []byte(fixtureOTPRecipient), []byte("other@example.test")),
		"wrong subject":   bytes.ReplaceAll(raw, []byte(proofOTPEmailSubject), []byte("Other subject")),
	} {
		t.Run(name, func(t *testing.T) {
			code, matches, err := extractProofOTP(changed, fixtureOTPRecipient, "qurl-go-sandbox-123-1")
			if err != nil || matches || code != "" {
				t.Fatalf("stale message = %q, %t, %v", code, matches, err)
			}
		})
	}

	ambiguous := append(append([]byte(nil), raw...), []byte("\r\nYour qURL Connector verification code is: 87654321\r\n")...)
	if _, _, err := extractProofOTP(ambiguous, fixtureOTPRecipient, "qurl-go-sandbox-123-1"); err == nil ||
		strings.Contains(err.Error(), "12345678") || strings.Contains(err.Error(), "87654321") {
		t.Fatalf("ambiguous code error was absent or disclosed a code: %v", err)
	}
}
