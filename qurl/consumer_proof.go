package qurl

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
)

// Consumer proof purposes separate metadata, enrollment, and admission.
const (
	ConsumerProofInfo   = "info"
	ConsumerProofEnroll = "enroll"
	ConsumerProofAdmit  = "admit"
)

// ConsumerProof binds an operation to the credential and its contact decision.
// Build it from validated request data and the live resource/invitation facts.
type ConsumerProof struct {
	Purpose              string `json:"purpose"`
	CRID                 string `json:"crid"`
	CredentialKind       string `json:"credential_kind"`
	CredentialID         string `json:"credential_id"`
	CredentialPublicKey  string `json:"credential_public_key_b64"`
	AuthenticatedPeerKey string `json:"authenticated_peer_key_b64"`
	AdmissionPublicKey   string `json:"admission_public_key_b64"`
	Email                string `json:"email"`
	DiscloseEmail        bool   `json:"disclose_email"`
	InvitationID         string `json:"invitation_id"`
	Nonce                string `json:"nonce"`
	PolicyVersion        int64  `json:"policy_version"`
	InvitationVersion    int64  `json:"invitation_version"`
	GrantVersion         int64  `json:"grant_version"`
	IssuedAt             int64  `json:"issued_at"`
}

// Challenge has a length-prefixed UTF-8 wire encoding, independent of JSON escaping.
func (p *ConsumerProof) Challenge() ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if p == nil || p.PolicyVersion < 0 || p.PolicyVersion > 1<<53-1 || p.InvitationVersion < 0 || p.InvitationVersion > 1<<53-1 ||
		p.GrantVersion < 0 || p.GrantVersion > 1<<53-1 || p.IssuedAt < 1 || p.IssuedAt > 1<<53-1 {
		return result, errors.New("consumer proof versions or time are invalid")
	}
	switch p.Purpose {
	case ConsumerProofInfo, ConsumerProofEnroll, ConsumerProofAdmit:
	default:
		return result, errors.New("consumer proof purpose is invalid")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(p.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != p.Nonce {
		return result, errors.New("consumer proof nonce is invalid")
	}
	h := sha256.New()
	h.Write([]byte("qurl-consumer-proof-v1\x00"))
	for _, value := range []string{
		p.Purpose, p.CRID, p.CredentialKind, p.CredentialID, p.CredentialPublicKey,
		p.AuthenticatedPeerKey, p.AdmissionPublicKey, p.Email, strconv.FormatBool(p.DiscloseEmail),
		p.InvitationID, p.Nonce,
	} {
		length := len(value)
		if length < 0 || length > 1024 {
			return result, errors.New("consumer proof field is too large")
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(length))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	for _, value := range []int64{p.PolicyVersion, p.InvitationVersion, p.GrantVersion, p.IssuedAt} {
		if value < 0 || value > 1<<53-1 {
			return result, errors.New("consumer proof number is out of range")
		}
		var number [8]byte
		binary.BigEndian.PutUint64(number[:], uint64(value))
		h.Write(number[:])
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}
