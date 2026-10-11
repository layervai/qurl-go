package qurl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"

	"github.com/layervai/qurl-go/relayknock"
)

// ConsumerEnrollmentClient sends private operations under one consumer-owned peer key.
// It discovers support before sending mailbox, invitation or continuation secrets.
type ConsumerEnrollmentClient struct {
	resourceCRID string
	cfg          Config
	peerKey      []byte
	mu           sync.Mutex
	supported    bool
}

// NewConsumerEnrollmentClient copies an existing peer key; it never replaces local identity.
func NewConsumerEnrollmentClient(resourceCRID string, peerKey []byte, cfg Config) (*ConsumerEnrollmentClient, error) {
	if err := validateCRIDForLinkRequest(resourceCRID); err != nil {
		return nil, err
	}
	if cfg.ExpectedCRID != "" && cfg.ExpectedCRID != resourceCRID {
		return nil, ErrCRIDMismatch
	}
	if err := validateCRIDLinkDeviceKey(peerKey); err != nil {
		return nil, fmt.Errorf("%w: invalid consumer peer key", ErrInvalidClientConfig)
	}
	if _, err := resolveCRIDLinkEndpoint(cfg); err != nil {
		return nil, err
	}
	return &ConsumerEnrollmentClient{resourceCRID: resourceCRID, cfg: cfg, peerKey: append([]byte(nil), peerKey...)}, nil
}

// ConsumerEnrollmentOperation keeps enrollment secrets out of display metadata.
type ConsumerEnrollmentOperation struct {
	Action              string                   `json:"action"`
	Input               *ConsumerEnrollmentInput `json:"input,omitempty"`
	InvitationToken     string                   `json:"invitation_token,omitempty"`
	EnrollmentReference string                   `json:"enrollment_reference,omitempty"`
	VerificationCode    string                   `json:"verification_code,omitempty"`
	AdmissionPublicKey  string                   `json:"admission_public_key_b64,omitempty"`
}

// ConsumerEnrollmentInput carries the credential proof and optional invitation.
type ConsumerEnrollmentInput struct {
	Proof           ConsumerProof             `json:"proof"`
	Assertion       *ConsumerPasskeyAssertion `json:"assertion,omitempty"`
	InvitationToken string                    `json:"invitation_token,omitempty"`
}

// ConsumerPasskeyAssertion uses standard padded base64 for WebAuthn buffers.
type ConsumerPasskeyAssertion struct {
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
	IssuedAt          int64  `json:"issued_at"`
}

// String redacts all operation values, including invitation and mailbox secrets.
func (o ConsumerEnrollmentOperation) String() string {
	return "qurl.ConsumerEnrollmentOperation{[REDACTED]}"
}

// GoString redacts all operation values in formatted output.
func (o ConsumerEnrollmentOperation) GoString() string { return o.String() }

// Exchange returns authenticated metadata. Minted claims still require issuer,
// held-CRID and leaf-key verification before admission.
func (c *ConsumerEnrollmentClient) Exchange(ctx context.Context, operation ConsumerEnrollmentOperation) (json.RawMessage, error) {
	if c == nil {
		return nil, ErrInvalidClientConfig
	}
	c.mu.Lock()
	supported := c.supported
	c.mu.Unlock()
	if !supported {
		info, err := c.exchange(ctx, ConsumerEnrollmentOperation{Action: "info"})
		if err != nil {
			return nil, err
		}
		if operation.Action == "info" && operation.InvitationToken == "" {
			return info, nil
		}
	}
	return c.exchange(ctx, operation)
}

func (c *ConsumerEnrollmentClient) exchange(ctx context.Context, operation ConsumerEnrollmentOperation) (json.RawMessage, error) {
	switch operation.Action {
	case "info", "enroll", "prove", "contract", "verify", "status", "mint":
	default:
		return nil, fmt.Errorf("%w: unknown consumer operation", ErrInvalidResourceRequest)
	}
	encoded, err := json.Marshal(operation)
	defer wipeBytes(encoded)
	if err != nil || len(encoded) > 3072 {
		return nil, fmt.Errorf("%w: consumer operation exceeds size limit", ErrInvalidResourceRequest)
	}
	endpoint, err := resolveCRIDLinkEndpoint(c.cfg)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		HeaderType int            `json:"headerType"`
		AspID      string         `json:"aspId"`
		ResID      string         `json:"resId"`
		UserData   map[string]any `json:"usrData"`
	}{nhpKNKHeaderType, qurlAspID, "qurl-crid-enroll", map[string]any{"qurl_crid": c.resourceCRID, "qurl_enrollment": operation}})
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	reply, err := relayknock.Knock(ctx, endpoint.relayURL, endpoint.serverPublicKey, body, relayknock.KnockOptions{HTTPClient: c.cfg.HTTPClient, DeviceStaticPriv: c.peerKey})
	if err != nil {
		return nil, cridLinkTransportError(ctx, err)
	}
	if reply == nil {
		return nil, ErrCRIDLinkProtocol
	}
	defer wipeBytes(reply.Body)
	if reply.IsCookieChallenge() {
		return nil, ErrServerOverloaded
	}
	if !reply.IsACK() {
		return nil, ErrCRIDLinkProtocol
	}
	ack, ok := decodeCRIDLinkACK(reply.Body)
	if !ok {
		return nil, ErrCRIDLinkProtocol
	}
	code, ok := cridLinkJSONString(ack["errCode"])
	if !ok {
		return nil, ErrCRIDLinkProtocol
	}
	if code != "52609" {
		if denial, known := cridLinkDenials[code]; known {
			return nil, denial
		}
		return nil, ErrCRIDLinkProtocol
	}
	metadata, ok := cridLinkJSONObject(ack["redirectInfo"])
	if !ok {
		return nil, ErrCRIDLinkProtocol
	}
	action, ok := cridLinkJSONString(metadata["action"])
	if !ok || action != operation.Action || string(metadata["version"]) != "1" {
		return nil, ErrCRIDLinkProtocol
	}
	data, ok := cridLinkJSONObject(metadata["data"])
	if !ok || len(data) == 0 {
		return nil, ErrCRIDLinkProtocol
	}
	if action == "info" || action == "mint" {
		responseCRID, ok := cridLinkJSONString(data["crid"])
		if !ok || responseCRID != c.resourceCRID {
			return nil, ErrCRIDMismatch
		}
	}
	if action == "info" {
		var info struct {
			Policy     ConsumerAccessPolicy `json:"policy"`
			Origin     string               `json:"origin"`
			RPID       string               `json:"relying_party_id"`
			ServerTime int64                `json:"server_time"`
		}
		if json.Unmarshal(metadata["data"], &info) != nil || info.Policy.validate() != nil || info.Origin == "" || info.RPID == "" || info.ServerTime < 1 || info.ServerTime >= 1<<53 {
			return nil, ErrCRIDLinkProtocol
		}
		origin, parseErr := url.Parse(info.Origin)
		if parseErr != nil || info.Origin != endpoint.linkOrigin || origin.Hostname() != info.RPID {
			return nil, ErrCRIDLinkProtocol
		}
		c.mu.Lock()
		c.supported = true
		c.mu.Unlock()
	}
	return append(json.RawMessage(nil), metadata["data"]...), nil
}

// String prevents a copied consumer peer key from appearing in logs.
func (c *ConsumerEnrollmentClient) String() string {
	return "qurl.ConsumerEnrollmentClient{[REDACTED]}"
}

// GoString redacts the copied peer key in formatted output.
func (c *ConsumerEnrollmentClient) GoString() string { return c.String() }
