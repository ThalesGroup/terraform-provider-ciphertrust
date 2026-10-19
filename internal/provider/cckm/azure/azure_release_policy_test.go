package cckm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestCckmAzureReleasePolicy is a plain unit test. It needs no CipherTrust Manager, vault or credentials.
// The name starts with TestCckmAzure so that it runs under the CCKM-AZURE test filter.
// Each check uses t.Errorf so that a failure does not stop the checks that follow it.
func TestCckmAzureReleasePolicy(t *testing.T) {
	const policy = `{"version":"1.0.0","anyOf":[{"authority":"https://example.com"}]}`
	const policyReordered = "{\n  \"anyOf\": [{\"authority\": \"https://example.com\"}],\n  \"version\": \"1.0.0\"\n}\n"
	const policyDifferent = `{"version":"1.0.0","anyOf":[{"authority":"https://other.example.com"}]}`

	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatalf("unable to write policy file: %v", err)
	}
	reorderedFile := filepath.Join(dir, "reordered.json")
	if err := os.WriteFile(reorderedFile, []byte(policyReordered), 0o600); err != nil {
		t.Fatalf("unable to write reordered policy file: %v", err)
	}

	// 1. Inline JSON is returned unchanged.
	if got, err := azureReleasePolicyContent(policy); err != nil || got != policy {
		t.Errorf("inline JSON: got %q, err %v, want the JSON unchanged", got, err)
	}

	// 2. A file path returns the contents of the file, never the file name.
	if got, err := azureReleasePolicyContent(policyFile); err != nil || got != policy {
		t.Errorf("file path: got %q, err %v, want the file contents", got, err)
	}

	// 3. A value that is neither JSON nor a file is rejected with an error diagnostic.
	var diags diag.Diagnostics
	if _, ok := azureReleasePolicyObject(filepath.Join(dir, "missing.json"), path.Root("release_policy"), &diags); ok || !diags.HasError() {
		t.Errorf("invalid value: ok = %v, HasError = %v, want false and true", ok, diags.HasError())
	}

	// 4. A file and inline JSON with a different key order and whitespace are equivalent.
	if !azureReleasePolicyEquivalent(reorderedFile, policy) {
		t.Errorf("equivalent: a file and inline JSON with the same content should be equal")
	}

	// 5. Different content is not equivalent.
	if azureReleasePolicyEquivalent(policy, policyDifferent) {
		t.Errorf("different content: should not be equal")
	}

	// 6 and 7 use the immutable plan modifier on an existing resource.
	nonNullRaw := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}, map[string]tftypes.Value{})
	modify := func(state, plan string) *planmodifier.StringResponse {
		req := planmodifier.StringRequest{
			Path:       path.Root("release_policy"),
			State:      tfsdk.State{Raw: nonNullRaw},
			Plan:       tfsdk.Plan{Raw: nonNullRaw},
			StateValue: types.StringValue(state),
			PlanValue:  types.StringValue(plan),
		}
		resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}
		azureReleasePolicyImmutable().PlanModifyString(context.Background(), req, resp)
		return resp
	}

	// 6. A file with equivalent JSON is not a change. There is no error and the state value is kept.
	resp := modify(policy, reorderedFile)
	if resp.Diagnostics.HasError() || resp.PlanValue.ValueString() != policy {
		t.Errorf("immutable, equivalent file: HasError = %v, plan value = %q, want no error and the state value", resp.Diagnostics.HasError(), resp.PlanValue.ValueString())
	}

	// 7. A real change is an error.
	if resp := modify(policy, policyDifferent); !resp.Diagnostics.HasError() {
		t.Errorf("immutable, changed policy: want an error, got none")
	}
}
