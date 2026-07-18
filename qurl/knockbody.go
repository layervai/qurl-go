package qurl

import (
	"encoding/json"
	"fmt"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// qURL knock-body construction.
//
// PROVISIONAL WIRE SHAPE. The qURL server admission contract (the qURL
// keyed-identity design's "NHP Server Contract" section) is Proposed, not deployed,
// and the encrypted knock-body field layout is not yet frozen.
// This builder encodes what the design specifies for the CLIENT side of the knock
// (section "Browser and Headless Flow", steps 5–6):
//
//   - the NHP knock resource identity (resId) is the protected-resource public key
//     (resource_public_key_b64);
//   - the signed qURL claims travel in encrypted knock user data; the field names
//     mirror the server contract's separate blobs qurl_claims_b64 /
//     qurl_issuer_sig_b64 so a verifier reads exactly the signed bytes.
//
// The per-qURL public key is NOT placed in the body: the server learns it as the
// authenticated Noise initiator static key (IK handshake) and matches it to the
// signed qurl_user_public_key_b64. relayknock seals this body into the knock with
// the per-qURL private key as the agent identity, completing proof-of-possession.
//
// When the server contract freezes, only this one function changes — the verb,
// the parse/verify, the relay routing, and the handshake stay put. The mismatch
// surfaces as a server deny, not a silent wrong-resource open, because admission
// re-verifies the signature and the cell/resource/key bindings.

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
)

// Native session-control body header values must exactly match their outer NHP
// packet types. Keeping them together makes it hard for a re-knock or clean
// exit to accidentally reuse the ordinary KNK body envelope.
const (
	nhpKNKHeaderType = relayknock.TypeKnock
	nhpRKNHeaderType = relayknock.TypeReknock
	nhpEXTHeaderType = relayknock.TypeExit
)

// buildKnockBody serializes the provisional qURL knock body for a verified fragment:
// resId = resource_public_key_b64, usrData = the signed claims + issuer signature,
// taken verbatim from the wire so the server verifies the exact signed bytes.
func buildKnockBody(frag *qv2.Fragment) ([]byte, error) {
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
			claimsUserDataKey: frag.ClaimsB64,
			sigUserDataKey:    frag.SigB64,
		},
	})
}
