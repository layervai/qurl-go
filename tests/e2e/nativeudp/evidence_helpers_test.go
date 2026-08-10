package nativeudp_test

// Helpers shared by the evidence tests that outlived the attended sandbox
// proof. These were defined alongside the sandbox configuration loader; the
// loader was removed with the proof, but the evidence and fault-path tests
// that run in ordinary CI still depend on them.

const (
	// Read by the orchestrator-evidence test to decide whether a missing
	// evidence bundle is a hard failure. Unset in ordinary CI, which selects
	// the non-strict path.
	strictEnv                = "QURL_GO_SANDBOX_STRICT"
	buildSHAEnv              = "QURL_GO_SANDBOX_EXPECTED_SHA"
	deploymentManifestSHAEnv = "QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"

	// An X25519 public key is always 32 bytes; a state blob carrying any
	// other length is malformed rather than merely unexpected.
	x25519PublicKeyLength = 32
)

// canonicalLowerHex reports whether value is exactly size lowercase hex
// digits. Evidence rows are compared as strings, so an uppercase or
// short-form digest would silently never match.
func canonicalLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range len(value) {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}
