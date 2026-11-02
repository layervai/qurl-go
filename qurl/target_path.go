package qurl

import (
	"net/url"
	"regexp"
	"strings"
)

// TODO(upstream-contract): qurl-service ValidateTargetPath and released
// qurl-conformance target_path_v1_vectors define this grammar without normalization.
var portalTargetPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()*+,;=:@%/?-]*$`)

func validPortalTargetPath(value string) bool {
	if value == "" || len(value) > maxTargetPathLength || strings.HasPrefix(value, "//") || !portalTargetPathPattern.MatchString(value) {
		return false
	}
	if _, err := url.PathUnescape(value); err != nil {
		return false
	}
	pathPart, _, _ := strings.Cut(value, "?")
	// Queries are preserved byte-for-byte; only the path defines authorization.
	if strings.ContainsAny(pathPart, "%!()*;") || strings.Contains(pathPart[1:], "//") {
		return false
	}
	for _, segment := range strings.Split(pathPart, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
