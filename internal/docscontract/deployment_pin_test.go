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
const revisitDocsMessage = `The embedded deployment changed. Review the production-default instructions in
README.md (Quickstart, "Connect a service or agent", "Opening links"),
docs/opening-links.md, docs/register-an-agent.md, and docs/testing-against-nhp.md.
They promise embedded production issuer keys, native cell endpoints, and a Hub
trust root, with QURL_DEPLOYMENT reserved for sandbox or custom deployments.
Update the documentation and this contract together if that behavior changes.`

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestEmbeddedDeploymentProvidesProductionDefaults guards the configuration
// required by the zero-configuration production setup in the README and guides.
// Key values can rotate without changing that documented setup.
func TestEmbeddedDeploymentProvidesProductionDefaults(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "qurl", "deployment.json"))
	if err != nil {
		t.Fatalf("reading embedded deployment: %v", err)
	}

	var dep map[string]json.RawMessage
	if err := json.Unmarshal(data, &dep); err != nil {
		t.Fatalf("qurl/deployment.json is not a JSON object: %v", err)
	}

	want := []string{"cells", "hub", "issuers", "relay_allowlist"}
	if got := slices.Sorted(maps.Keys(dep)); !slices.Equal(got, want) {
		t.Fatalf("qurl/deployment.json keys are %v, want exactly %v.\n\n%s",
			got, want, revisitDocsMessage)
	}
	for _, key := range []string{"cells", "issuers", "relay_allowlist"} {
		var arr []json.RawMessage
		if err := json.Unmarshal(dep[key], &arr); err != nil {
			t.Fatalf("qurl/deployment.json %q is not a JSON array: %v\n\n%s", key, err, revisitDocsMessage)
		}
		if len(arr) == 0 {
			t.Fatalf("qurl/deployment.json %q has %d entry(ies); production defaults require a nonempty array.\n\n%s",
				key, len(arr), revisitDocsMessage)
		}
	}
	var hub struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		Key  string `json:"server_public_key_b64"`
	}
	if err := json.Unmarshal(dep["hub"], &hub); err != nil {
		t.Fatalf("decoding embedded Hub: %v\n\n%s", err, revisitDocsMessage)
	}
	if hub.Host != "hub.nhp.layerv.ai" || hub.Port != 443 || hub.Key == "" {
		t.Fatalf("embedded Hub must provide the production endpoint and trust root\n\n%s", revisitDocsMessage)
	}
}
