package docscontract

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// revisitDocsMessage is appended to every tier 3 failure: the pin exists to
// force a documentation rewrite, not to protect the JSON file.
const revisitDocsMessage = `The embedded deployment changed, so the documentation's trust story is now stale:
README.md (Quickstart, "Connect a service or agent", "Opening links"),
docs/opening-links.md, docs/register-an-agent.md, and docs/testing-against-nhp.md
are all written for the pre-GA posture in which QURL_DEPLOYMENT (or an installed
Provider) supplies the trust roots BECAUSE the build embeds an empty deployment.
Rewrite the quickstart and guides for the newly embedded deployment first, then
update this pin to the new shape. This failure is the drift gate working as
designed — do not silence it by editing only this test.`

// TestEmbeddedDeploymentStaysPreGAEmpty is tier 3: it pins
// qurl/deployment.json — the deployment embedded in every build — to its
// exact pre-GA shape: "issuers", "cells", and "relay_allowlist" all present
// and empty, and no other key, in particular NO "hub" trust root.
//
// Intent: the README and guides teach that native opens and agent enrollment
// need a deployment file from LayerV setup precisely because current releases
// embed an empty deployment. When GA (or anything else) embeds a real
// deployment, that story becomes wrong everywhere at once, so this test MUST
// fail and force the quickstart and guides to be rewritten. The failure is
// the feature.
func TestEmbeddedDeploymentStaysPreGAEmpty(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "qurl", "deployment.json"))
	if err != nil {
		t.Fatalf("reading embedded deployment: %v", err)
	}

	var dep map[string]json.RawMessage
	if err := json.Unmarshal(data, &dep); err != nil {
		t.Fatalf("qurl/deployment.json is not a JSON object: %v", err)
	}

	want := []string{"cells", "issuers", "relay_allowlist"}
	if got := slices.Sorted(maps.Keys(dep)); !slices.Equal(got, want) {
		t.Fatalf("qurl/deployment.json keys are %v, want exactly %v (the empty pre-GA deployment; note: no \"hub\").\n\n%s",
			got, want, revisitDocsMessage)
	}
	for _, key := range want {
		var arr []json.RawMessage
		if err := json.Unmarshal(dep[key], &arr); err != nil {
			t.Fatalf("qurl/deployment.json %q is not a JSON array: %v\n\n%s", key, err, revisitDocsMessage)
		}
		if len(arr) != 0 {
			t.Fatalf("qurl/deployment.json %q has %d entry(ies); the pre-GA embedded deployment is empty.\n\n%s",
				key, len(arr), revisitDocsMessage)
		}
	}
}
