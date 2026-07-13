package qurl

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	cycleRunIDEntropyBytes = 8
	cycleRunIDLength       = cycleRunIDEntropyBytes * 2
)

// ErrInvalidCycleRunID is returned when a connector cycle RunID is missing or
// noncanonical. A canonical cycle RunID is exactly 16 lowercase hexadecimal
// characters. Callers must not trim, case-fold, or otherwise normalize it.
var ErrInvalidCycleRunID = errors.New("qurl: invalid cycle run id")

// NewCycleRunID returns a new connector cycle RunID made from exactly eight
// bytes of cryptographic entropy and encoded as exactly 16 lowercase
// hexadecimal characters.
//
// The fixed 64-bit shape is the authenticated per-cycle correlation contract,
// not a long-lived globally unique identifier or a security token.
//
// qURL Connector owns the lifecycle of this value: generate it once per outer
// knock/service cycle and reuse the exact string for every retry and reconnect
// in that cycle. Native knock APIs validate and carry the caller-supplied value;
// they must not generate a replacement implicitly.
func NewCycleRunID() (string, error) {
	return newCycleRunID(rand.Reader)
}

func newCycleRunID(random io.Reader) (string, error) {
	var entropy [cycleRunIDEntropyBytes]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return "", fmt.Errorf("qurl: generate cycle run id: %w", err)
	}
	return hex.EncodeToString(entropy[:]), nil
}

// ValidateCycleRunID reports whether runID is the canonical connector cycle
// identifier: exactly 16 ASCII characters drawn from 0-9 and lowercase a-f.
// Missing values and alternate spellings fail; validation never trims or
// normalizes caller input.
func ValidateCycleRunID(runID string) error {
	if runID == "" {
		return fmt.Errorf("%w: must not be empty", ErrInvalidCycleRunID)
	}
	if len(runID) != cycleRunIDLength {
		return fmt.Errorf("%w: must be exactly %d lowercase hexadecimal characters", ErrInvalidCycleRunID, cycleRunIDLength)
	}
	for i := 0; i < len(runID); i++ {
		c := runID[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: character %d must be lowercase hexadecimal", ErrInvalidCycleRunID, i)
		}
	}
	return nil
}
