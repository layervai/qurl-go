package qurl

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ConsumerAdmission retains a verified leaf capability and same-visitor renewal state.
// It has no exported secret fields. Keep it in consumer-local memory or protected state.
type ConsumerAdmission struct {
	link string
	cfg  Config
}

// MintAdmission uses the same leaf key that the consumer proved during enrollment.
// It verifies issuer, held CRID and leaf binding before returning an opener.
func (c *ConsumerEnrollmentClient) MintAdmission(ctx context.Context, reference string, leafPrivateKey []byte) (*ConsumerAdmission, error) {
	if c == nil {
		return nil, ErrInvalidClientConfig
	}
	leaf, err := ecdh.X25519().NewPrivateKey(leafPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid admission key", ErrInvalidResourceRequest)
	}
	publicKey := base64.StdEncoding.EncodeToString(leaf.PublicKey().Bytes())
	raw, err := c.Exchange(ctx, ConsumerEnrollmentOperation{Action: "mint", EnrollmentReference: reference, AdmissionPublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	defer wipeBytes(raw)
	var response struct {
		ClaimsB64 string `json:"claims_b64"`
		SigB64    string `json:"sig_b64"`
		CRID      string `json:"crid"`
	}
	if json.Unmarshal(raw, &response) != nil || response.CRID != c.resourceCRID {
		return nil, ErrCRIDLinkProtocol
	}
	secret, err := json.Marshal(Secret{QurlUserPrivateKeyB64: base64.RawURLEncoding.EncodeToString(leafPrivateKey)})
	if err != nil {
		return nil, err
	}
	defer wipeBytes(secret)
	signature, err := decodeB64(response.SigB64)
	if err != nil {
		return nil, err
	}
	canonical, err := buildFragment(response.ClaimsB64, base64.RawURLEncoding.EncodeToString(secret), signature)
	if err != nil {
		return nil, err
	}
	transport, err := encodeTransportFragment(canonical)
	if err != nil {
		return nil, err
	}
	link := c.cfg.CRIDLink.LinkOrigin + "/#" + transport
	verified, err := VerifyLinkForCRID(link, c.resourceCRID, c.cfg.TrustStore)
	if err != nil {
		return nil, err
	}
	if verified.Claims.QurlUserPublicKeyB64 != base64.RawURLEncoding.EncodeToString(leaf.PublicKey().Bytes()) {
		return nil, fmt.Errorf("%w: admission leaf mismatch", ErrInvalidAPIResponse)
	}
	cfg := c.cfg
	cfg.ExpectedCRID = c.resourceCRID
	cfg.PortalSession = &PortalSession{}
	return &ConsumerAdmission{link: link, cfg: cfg}, nil
}

// Open opens or renews the same proved capability, retaining its visitor secret.
// Call again before the short network lease expires; do not mint a new leaf for renewal.
func (a *ConsumerAdmission) Open(ctx context.Context) (*ResourceHandle, error) {
	if a == nil {
		return nil, ErrInvalidClientConfig
	}
	return EnterPortalWith(ctx, a.link, a.cfg)
}

// String prevents the private leaf capability from appearing in logs.
func (a *ConsumerAdmission) String() string { return "qurl.ConsumerAdmission{[REDACTED]}" }

// GoString redacts the capability in formatted output.
func (a *ConsumerAdmission) GoString() string { return a.String() }

// MarshalJSON omits all admission and renewal secrets.
func (a *ConsumerAdmission) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
