package qv2

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// TransportPrefix is the versioned, share-safe envelope used by full qURL
// links. The cryptographic fragment inside the envelope remains qv2.
const TransportPrefix = "qv2t1"

const (
	transportChunkLength = 240

	// These limits bound the encoded qv2 fields before any split, join, or
	// decode allocation. They are protocol limits, not merely chunk-count
	// limits: the final chunk cannot be used to exceed them.
	transportMaxClaimsLength = 6144
	transportMaxSecretLength = 512
	transportMaxSigLength    = 128

	transportMaxClaimsChunks = (transportMaxClaimsLength + transportChunkLength - 1) / transportChunkLength
	transportMaxSecretChunks = (transportMaxSecretLength + transportChunkLength - 1) / transportChunkLength
	transportMaxSigChunks    = (transportMaxSigLength + transportChunkLength - 1) / transportChunkLength
	transportMaxChunks       = transportMaxClaimsChunks + transportMaxSecretChunks + transportMaxSigChunks

	canonicalFragmentMaxLength = len(FragmentPrefix) + 3 +
		transportMaxClaimsLength + transportMaxSecretLength + transportMaxSigLength
	// The decimal count-token widths are coupled to the maximum chunk counts
	// above. validateConformanceTransportContract pins the resulting maximum and
	// chunk counts to the released contract, so a future cap change cannot
	// silently make this maximum stale.
	transportFragmentMaxLength = len(TransportPrefix) + len("26") + len("3") + len("1") +
		3 + transportMaxChunks + transportMaxClaimsLength + transportMaxSecretLength + transportMaxSigLength
)

// EncodeTransportFragment wraps a canonical qv2 fragment in the share-safe
// qv2t1 transport. It preserves each encoded field byte-for-byte and inserts
// dots only at deterministic 240-character boundaries.
//
// The input and output are fragment bodies without a leading '#'.
func EncodeTransportFragment(fragment string) (string, error) {
	// Bound the input before Split allocates one string header per separator.
	if len(fragment) > canonicalFragmentMaxLength {
		return "", fmt.Errorf("%w: canonical fragment exceeds transport limit", ErrFragment)
	}

	parts := strings.Split(fragment, ".")
	if len(parts) != fragmentParts || parts[0] != FragmentPrefix {
		return "", fmt.Errorf("%w: transport input must be a canonical qv2 fragment", ErrFragment)
	}

	fields := []transportField{
		{name: "claims", value: parts[1], maxLength: transportMaxClaimsLength},
		{name: "secret", value: parts[2], maxLength: transportMaxSecretLength},
		{name: "signature", value: parts[3], maxLength: transportMaxSigLength},
	}
	for _, field := range fields {
		if err := validateTransportField(field); err != nil {
			return "", err
		}
		// Enforce the same unique, unpadded base64url representation used by the
		// canonical parser without parsing or reserializing either JSON payload.
		if _, err := decodeB64(field.value); err != nil {
			return "", fmt.Errorf("%w: %s field is not canonical base64url: %w", ErrFragment, field.name, err)
		}
	}

	claimsCount := chunkCount(len(fields[0].value))
	secretCount := chunkCount(len(fields[1].value))
	sigCount := chunkCount(len(fields[2].value))

	encoded := make([]string, 0, 4+claimsCount+secretCount+sigCount)
	encoded = append(encoded,
		TransportPrefix,
		strconv.Itoa(claimsCount),
		strconv.Itoa(secretCount),
		strconv.Itoa(sigCount),
	)
	for _, field := range fields {
		for start := 0; start < len(field.value); start += transportChunkLength {
			end := min(start+transportChunkLength, len(field.value))
			encoded = append(encoded, field.value[start:end])
		}
	}
	return strings.Join(encoded, "."), nil
}

// DecodeTransportFragment unwraps a qv2t1 fragment body into the exact
// canonical qv2 fragment consumed by ParseFragment. It validates only the
// transport envelope; ParseFragment remains the single strict parser for the
// reconstructed claims, secret, and signature.
func DecodeTransportFragment(fragment string) (string, error) {
	// This check is deliberately before Split: hostile separator-heavy input
	// cannot cause allocations proportional to an unbounded link.
	if len(fragment) > transportFragmentMaxLength {
		return "", fmt.Errorf("%w: transport fragment exceeds maximum length", ErrFragment)
	}

	parts := strings.Split(fragment, ".")
	if len(parts) < 4 || parts[0] != TransportPrefix {
		return "", fmt.Errorf("%w: expected %s transport fragment", ErrFragment, TransportPrefix)
	}

	claimsCount, err := parseTransportCount(parts[1], transportMaxClaimsChunks, "claims")
	if err != nil {
		return "", err
	}
	secretCount, err := parseTransportCount(parts[2], transportMaxSecretChunks, "secret")
	if err != nil {
		return "", err
	}
	sigCount, err := parseTransportCount(parts[3], transportMaxSigChunks, "signature")
	if err != nil {
		return "", err
	}

	wantParts := 4 + claimsCount + secretCount + sigCount
	if len(parts) != wantParts {
		return "", fmt.Errorf("%w: transport part count does not match declared counts", ErrFragment)
	}

	offset := 4
	claimsB64, err := joinTransportChunks(parts[offset:offset+claimsCount], transportMaxClaimsLength, "claims")
	if err != nil {
		return "", err
	}
	offset += claimsCount
	secretB64, err := joinTransportChunks(parts[offset:offset+secretCount], transportMaxSecretLength, "secret")
	if err != nil {
		return "", err
	}
	offset += secretCount
	sigB64, err := joinTransportChunks(parts[offset:offset+sigCount], transportMaxSigLength, "signature")
	if err != nil {
		return "", err
	}

	return strings.Join([]string{FragmentPrefix, claimsB64, secretB64, sigB64}, "."), nil
}

// IsCredentialLink reports whether link declares the qv2t1 credential-bearing
// fragment transport. It is intentionally a classifier, not a verifier: a
// malformed qv2t1 link must still be routed to the fail-closed opener instead
// of being mistaken for an ordinary URL that is safe to fetch directly.
// The retired pre-release qv2 transport is deliberately excluded: URL
// fragments are not sent by HTTP, and every current qURL reader rejects it.
func IsCredentialLink(link string) bool {
	// Do not apply the decoder's length limit at this routing boundary. An
	// oversized declared credential must still take the fail-closed opener path;
	// classifying it as an ordinary URL would turn a resource bound into a
	// credential-handling bypass.
	if _, err := url.Parse(link); err != nil {
		return false
	}
	hash := strings.IndexByte(link, '#')
	return hash >= 0 && strings.HasPrefix(link[hash+1:], TransportPrefix+".")
}

type transportField struct {
	name      string
	value     string
	maxLength int
}

func validateTransportField(field transportField) error {
	if len(field.value) == 0 || len(field.value) > field.maxLength {
		return fmt.Errorf("%w: %s field length is outside transport limits", ErrFragment, field.name)
	}
	if !isBase64URLAlphabet(field.value) {
		return fmt.Errorf("%w: %s field contains a non-base64url character", ErrFragment, field.name)
	}
	return nil
}

func chunkCount(length int) int {
	return (length + transportChunkLength - 1) / transportChunkLength
}

func parseTransportCount(encoded string, maxCount int, fieldName string) (int, error) {
	if encoded == "" || encoded[0] == '0' {
		return 0, fmt.Errorf("%w: %s chunk count is not canonical", ErrFragment, fieldName)
	}
	count := 0
	for i := range len(encoded) {
		if encoded[i] < '0' || encoded[i] > '9' {
			return 0, fmt.Errorf("%w: %s chunk count is not canonical", ErrFragment, fieldName)
		}
		count = count*10 + int(encoded[i]-'0')
		if count > maxCount {
			return 0, fmt.Errorf("%w: %s chunk count exceeds maximum", ErrFragment, fieldName)
		}
	}
	return count, nil
}

func joinTransportChunks(chunks []string, maxLength int, fieldName string) (string, error) {
	total := 0
	for i, chunk := range chunks {
		if len(chunk) == 0 || len(chunk) > transportChunkLength {
			return "", fmt.Errorf("%w: %s chunk length is outside transport limits", ErrFragment, fieldName)
		}
		if i < len(chunks)-1 && len(chunk) != transportChunkLength {
			return "", fmt.Errorf("%w: non-final %s chunk must be exactly %d characters", ErrFragment, fieldName, transportChunkLength)
		}
		if !isBase64URLAlphabet(chunk) {
			return "", fmt.Errorf("%w: %s chunk contains a non-base64url character", ErrFragment, fieldName)
		}
		if total > maxLength-len(chunk) {
			return "", fmt.Errorf("%w: %s field exceeds transport limit", ErrFragment, fieldName)
		}
		total += len(chunk)
	}

	var joined strings.Builder
	joined.Grow(total)
	for _, chunk := range chunks {
		joined.WriteString(chunk)
	}
	return joined.String(), nil
}

func isBase64URLAlphabet(value string) bool {
	for i := range len(value) {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}
