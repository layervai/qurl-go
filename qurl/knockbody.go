package qurl

import (
	"encoding/json"
	"fmt"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// qURL knock-body construction.
//
// This builder puts qURL ASP verification data in the encrypted NHP knock:
//
//   - the NHP knock resource identity (resId) is the protected-resource public key
//     (resource_public_key_b64);
//   - the signed qURL claims travel in encrypted knock user data; the field names
//     mirror the server contract's separate blobs qurl_claims_b64 /
//     qurl_issuer_sig_b64 so a verifier reads exactly the signed bytes.
//   - qurl_session_secret carries this visitor's independent capability; the
//     NHP qURL ASP hashes it for service-side renewal matching.
//
// The per-qURL public key is NOT placed in the body: the server learns it as the
// authenticated Noise initiator static key (IK handshake) and matches it to the
// signed qurl_user_public_key_b64. relayknock seals this body into the knock with
// the per-qURL private key as the agent identity, completing proof-of-possession.
//
// These are qURL ASP user-data fields, not new NHP protocol fields. The qURL ASP
// reads its named keys from the existing UserData map. Packet headers, handshake,
// and the shared link's signed envelope keep their existing formats.

// qurlAspID is the NHP authorization-service-provider id for the qURL path.
const qurlAspID = "qurl"

// agentKnockMsg is the uncompressed knock body envelope (Go common.AgentKnockMsg).
// usrData map keys sort alphabetically in encoding/json.
type agentKnockMsg struct {
	HeaderType int               `json:"headerType"`
	AspID      string            `json:"aspId"`
	ResID      string            `json:"resId"`
	UsrData    map[string]string `json:"usrData,omitempty"`
}

// User-data keys carrying the signed qURL claim envelope (mirroring the NHP Server
// Contract blob names).
const (
	claimsUserDataKey = "qurl_claims_b64"
	sigUserDataKey    = "qurl_issuer_sig_b64"
	// This per-visitor secret is independent of the shared link key. NHP hashes
	// its decoded bytes to bind the service-side renewal proof.
	visitorCapabilityUserDataKey = "qurl_session_secret"
)

// Native session-control body header values must exactly match their outer NHP
// packet types. Keeping them together makes it hard for a re-knock or clean
// exit to accidentally reuse the ordinary KNK body envelope.
const (
	nhpKNKHeaderType = relayknock.TypeKnock
	nhpRKNHeaderType = relayknock.TypeReknock
	nhpEXTHeaderType = relayknock.TypeExit
)

// buildKnockBody serializes the qURL knock body for a verified fragment:
// resId = resource_public_key_b64, usrData = the signed claims + issuer signature,
// taken verbatim from the wire so the server verifies the exact signed bytes.
func buildKnockBody(frag *qv2.Fragment, sessionSecret string) ([]byte, error) {
	if frag == nil || frag.Claims == nil {
		return nil, fmt.Errorf("qurl: build knock body: fragment not parsed")
	}
	if frag.Claims.ResourcePublicKeyB64 == "" {
		return nil, fmt.Errorf("qurl: build knock body: missing resource_public_key_b64")
	}
	return json.Marshal(agentKnockMsg{
		HeaderType: nhpKNKHeaderType,
		AspID:      qurlAspID,
		ResID:      frag.Claims.ResourcePublicKeyB64,
		UsrData: map[string]string{
			claimsUserDataKey:            frag.ClaimsB64,
			sigUserDataKey:               frag.SigB64,
			visitorCapabilityUserDataKey: sessionSecret,
		},
	})
}
