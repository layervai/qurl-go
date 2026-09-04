package qurl

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/layervai/qurl-go/internal/qv2"
)

// ErrPortalSessionLinkMismatch means a PortalSession was reused for a different
// verified qURL. Create a separate PortalSession for each received link.
var ErrPortalSessionLinkMismatch = errors.New("qurl: portal session belongs to another link")

// PortalSession holds the private visitor capability for one verified qURL.
// Its zero value is ready for use. Retain the same pointer in Config.PortalSession
// to retry after a lost reply or renew that visitor's access. With server
// renewal-proof enforcement, a new session cannot recover a previous visitor's
// single-use grant, even with the same link.
//
// The capability is generated after link verification and never comes from the
// link's shared key. Keep this object in memory and do not copy it after use.
// It is safe for concurrent calls. It has no JSON fields or public secret getter.
type PortalSession struct {
	mu    sync.Mutex
	state *portalSessionState
}

type portalSessionState struct {
	identity [sha256.Size]byte
	secret   string
}

// String returns a redacted representation of the visitor capability.
func (*PortalSession) String() string { return "qurl.PortalSession{[REDACTED]}" }

// GoString returns the same redacted representation as String.
func (s *PortalSession) GoString() string { return s.String() }

// secretFor is called only after the signed claims and transport have passed
// verification. Binding to the exact signed envelope prevents an accidental
// shared Config from sending one visitor's capability for another link.
func (s *PortalSession) secretFor(frag *qv2.Fragment) (string, error) {
	identity := sha256.Sum256([]byte(frag.ClaimsB64 + "." + frag.SigB64))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		if s.state.identity != identity {
			return "", ErrPortalSessionLinkMismatch
		}
		return s.state.secret, nil
	}

	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("qurl: create portal session: %w", err)
	}
	s.state = &portalSessionState{identity: identity, secret: b64url.EncodeToString(secret[:])}
	return s.state.secret, nil
}
