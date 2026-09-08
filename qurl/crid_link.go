package qurl

import (
	"context"
	"fmt"

	"github.com/layervai/qurl-go/crid"
)

// VerifyLinkForCRID verifies the issuer signature and binds the signed resource
// key to an independently obtained CRID. It does not verify content or liveness.
// Never obtain expectedCRID from the same untrusted response as qurlLink.
func VerifyLinkForCRID(qurlLink, expectedCRID string, ts *TrustStore) (*Fragment, error) {
	if err := validateExpectedCRID(expectedCRID); err != nil {
		return nil, err
	}
	fragment, err := VerifyLink(qurlLink, ts)
	if err != nil {
		return nil, err
	}
	key, err := decodeResourcePublicKey(fragment.Claims.ResourcePublicKeyB64)
	if err != nil {
		return nil, err
	}
	matched, err := crid.KeyMatches(expectedCRID, key)
	if err != nil || !matched {
		return nil, ErrCRIDMismatch
	}
	return fragment, nil
}

func validateExpectedCRID(value string) error {
	if value == "" {
		return ErrNoCRID
	}
	parsed, err := crid.Parse(value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCRIDMismatch, err)
	}
	if !parsed.Known() {
		return fmt.Errorf("%w: unsupported CRID version", ErrCRIDMismatch)
	}
	return nil
}

// VerifyPortalLink uses the configured deployment trust to verify a link's
// issuer and expected CRID without requesting access or fetching content.
func VerifyPortalLink(ctx context.Context, qurlLink, expectedCRID string) error {
	if err := validateExpectedCRID(expectedCRID); err != nil {
		return err
	}
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return err
	}
	_, err = VerifyLinkForCRID(qurlLink, expectedCRID, cfg.TrustStore)
	return err
}

// EnterPortalForCRID opens a link only if its signed key matches the CRID held
// by the caller. Deployment trust is resolved as for EnterPortal.
func EnterPortalForCRID(ctx context.Context, qurlLink, expectedCRID string) (*ResourceHandle, error) {
	if err := validateExpectedCRID(expectedCRID); err != nil {
		return nil, err
	}
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	cfg.ExpectedCRID = expectedCRID
	return EnterPortalWith(ctx, qurlLink, cfg)
}
