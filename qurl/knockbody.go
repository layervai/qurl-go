package qurl

import (
	"encoding/json"
	"fmt"

	"github.com/layervai/qurl-go/internal/qv2"
)

// qURL v2 knock-body construction.
//
// PROVISIONAL WIRE SHAPE. The qURL server admission contract (the qURL v2
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

// qv2AspID is the NHP authorization-service-provider id for the qURL path.
const qv2AspID = "qurl"

// agentKnockMsg is the uncompressed knock body envelope (Go common.AgentKnockMsg).
// usrData map keys sort alphabetically in encoding/json.
type agentKnockMsg struct {
	HeaderType int               `json:"headerType"`
	AspID      string            `json:"aspId"`
	ResID      string            `json:"resId"`
	UsrData    map[string]string `json:"usrData,omitempty"`
}

// User-data keys carrying the signed qURL v2 claim envelope (mirroring the NHP
// Server Contract blob names).
const (
	qv2ClaimsUserDataKey = "qurl_claims_b64"
	qv2SigUserDataKey    = "qurl_issuer_sig_b64"
)

// nhpKNKHeaderType is the NHP_KNK header-type value echoed in the body envelope
// (the KNK packet header-type, value 1).
const nhpKNKHeaderType = 1

// buildQv2KnockBody serializes the provisional qURL v2 knock body for a verified
// fragment: resId = resource_public_key_b64, usrData = the signed claims + issuer
// signature, taken verbatim from the wire so the server verifies the exact signed
// bytes.
func buildQv2KnockBody(frag *qv2.Fragment) ([]byte, error) {
	if frag == nil || frag.Claims == nil {
		return nil, fmt.Errorf("qurl: build knock body: fragment not parsed")
	}
	if frag.Claims.ResourcePublicKeyB64 == "" {
		return nil, fmt.Errorf("qurl: build knock body: missing resource_public_key_b64")
	}
	return json.Marshal(agentKnockMsg{
		HeaderType: nhpKNKHeaderType,
		AspID:      qv2AspID,
		ResID:      frag.Claims.ResourcePublicKeyB64,
		UsrData: map[string]string{
			qv2ClaimsUserDataKey: frag.ClaimsB64,
			qv2SigUserDataKey:    frag.SigB64,
		},
	})
}
