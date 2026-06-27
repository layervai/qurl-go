package qv2

import (
	"fmt"
	"net/url"
	"strings"
)

// relay_url validation.
//
// Per the design, relay_url "must be HTTPS, must pass the qURL deployment
// allowlist, and is used only after client-side issuer signature verification
// succeeds." This is therefore a SEPARATE step from parsing/verifying: a caller
// runs ValidateRelayURL only after Fragment.Verify returns nil. Keeping it out of
// the parser and out of Verify prevents acting on an attacker-chosen relay_url
// before the signature is known good, and keeps the allowlist (deployment config)
// out of the pure crypto core.

// RelayAllowlist is the set of host[:port] origins a relay_url may target. It is
// supplied from deployment config. An empty allowlist rejects every relay_url
// (fail closed) — a deployment must explicitly enumerate its relays.
type RelayAllowlist struct {
	hosts map[string]struct{}
}

// NewRelayAllowlist builds an allowlist from host or host:port entries. Entries
// are compared case-insensitively on host. An entry without a port matches any
// port for that host; an entry with a port matches only that exact host:port.
func NewRelayAllowlist(entries []string) *RelayAllowlist {
	hosts := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		hosts[e] = struct{}{}
	}
	return &RelayAllowlist{hosts: hosts}
}

// ValidateRelayURL validates a claim's relay_url against the HTTPS requirement
// and the allowlist. It MUST be called only after the issuer signature has been
// verified. It returns nil when the URL is acceptable, or a wrapped ErrRelayURL.
func ValidateRelayURL(relayURL string, allow *RelayAllowlist) error {
	if allow == nil {
		return fmt.Errorf("%w: no allowlist configured", ErrRelayURL)
	}
	u, err := url.Parse(relayURL)
	if err != nil {
		return fmt.Errorf("%w: unparseable url: %w", ErrRelayURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: scheme must be https, got %q", ErrRelayURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrRelayURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo not permitted", ErrRelayURL)
	}

	host := strings.ToLower(u.Host) // includes :port when present
	hostname := strings.ToLower(u.Hostname())

	if _, ok := allow.hosts[host]; ok {
		return nil
	}
	// Allow a hostname-only allowlist entry to match any port.
	if _, ok := allow.hosts[hostname]; ok {
		return nil
	}
	return fmt.Errorf("%w: host %q is not on the relay allowlist", ErrRelayURL, host)
}
