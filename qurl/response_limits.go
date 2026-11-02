package qurl

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Joint Go/TypeScript policy: qurl-typescript/docs/api-response-limits.md.
const maxConfigurableAPIResponseBodyBytes = 16 << 20

// WithMaxResponseBodyBytes sets the resource Client's decoded API response cap.
// The default is 1 MiB; an explicit cap must be from 1 byte through 16 MiB.
// The option also applies to Clients returned by native agent lifecycle calls;
// it does not change the native UDP protocol's message bounds.
func WithMaxResponseBodyBytes(limit int) AgentResourceClientOption {
	return responseBodyLimitOption(limit)
}

type responseBodyLimitOption int

func (o responseBodyLimitOption) applyClientOption(cfg *clientOptions) error {
	if o < 1 || o > maxConfigurableAPIResponseBodyBytes {
		return fmt.Errorf("%w: max response body bytes must be from 1 through 16777216", ErrInvalidClientConfig)
	}
	cfg.maxResponseBodyBytes = int(o)
	return nil
}

func (o responseBodyLimitOption) applyAgentRuntimeOption(cfg *nativeAgentRuntimeConfig) error {
	if o < 1 || o > maxConfigurableAPIResponseBodyBytes {
		return fmt.Errorf("%w: max response body bytes must be from 1 through 16777216", ErrInvalidRegisterConfig)
	}
	cfg.maxResponseBodyBytes = int(o)
	return nil
}

func (responseBodyLimitOption) isAgentRuntimeRegistrationOption() {}
func (responseBodyLimitOption) isAgentRuntimeRefreshOption()      {}
func (responseBodyLimitOption) isAgentRuntimeRecoveryOption()     {}

// Match the TypeScript client's conservative header hint. Decoded streaming
// accounting still decides when the header is missing, malformed or false-small.
func apiContentLengthExceedsLimit(response *http.Response, limit int) bool {
	if limit < 1 {
		return false
	}
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusResetContent || response.StatusCode == http.StatusNotModified || response.Uncompressed {
		return false
	}
	encoding := strings.TrimSpace(strings.Join(response.Header.Values("Content-Encoding"), ", "))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false
	}
	values := response.Header.Values("Content-Length")
	if len(values) != 1 {
		return false
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	size, err := strconv.ParseUint(value, 10, 64)
	return errors.Is(err, strconv.ErrRange) || (err == nil && size > uint64(limit))
}
