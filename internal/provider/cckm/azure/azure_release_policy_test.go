package cckm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
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

	// 8. Error messages. objectError returns the error text for a value, or "" if it was accepted.
	objectError := func(value string) string {
		var d diag.Diagnostics
		if _, ok := azureReleasePolicyObject(value, path.Root("release_policy"), &d); ok {
			return ""
		}
		if !d.HasError() {
			return "no error diagnostic"
		}
		return d.Errors()[0].Detail()
	}
	textFile := filepath.Join(dir, "not_json.txt")
	if err := os.WriteFile(textFile, []byte("this is not json"), 0o600); err != nil {
		t.Fatalf("unable to write text file: %v", err)
	}
	arrayFile := filepath.Join(dir, "array.json")
	if err := os.WriteFile(arrayFile, []byte(`[{"version":"1.0.0"}]`), 0o600); err != nil {
		t.Fatalf("unable to write array file: %v", err)
	}
	missingFile := filepath.Join(dir, "missing.json")

	// 8a. A missing file says that no file was found and names the path.
	if msg := objectError(missingFile); !strings.Contains(msg, "no file was found") || !strings.Contains(msg, "missing.json") {
		t.Errorf("missing file: message %q should say no file was found and name the file", msg)
	}
	// 8b. An existing file that is not JSON says the file is not valid, not that it was not found.
	if msg := objectError(textFile); !strings.Contains(msg, "does not contain a valid JSON object") || strings.Contains(msg, "no file was found") {
		t.Errorf("text file: message %q should say the file is not a valid JSON object", msg)
	}
	// 8c. An existing file that holds a JSON array is rejected because it is not an object.
	if msg := objectError(arrayFile); !strings.Contains(msg, "does not contain a valid JSON object") {
		t.Errorf("array file: message %q should say the file is not a valid JSON object", msg)
	}
	// 8d. Invalid inline JSON that looks like an object keeps the generic message.
	if msg := objectError(`{"version":`); !strings.Contains(msg, "valid JSON object or the path of a file") {
		t.Errorf("broken inline JSON: message %q should give the generic message", msg)
	}
	// 8e. A file with a valid object is accepted.
	if msg := objectError(policyFile); msg != "" {
		t.Errorf("valid file: unexpected error %q", msg)
	}

	// 9. A file that was valid when it was configured and is later edited is no longer equivalent.
	editedFile := filepath.Join(dir, "edited.json")
	if err := os.WriteFile(editedFile, []byte(policy), 0o600); err != nil {
		t.Fatalf("unable to write edited file: %v", err)
	}
	if !azureReleasePolicyEquivalent(editedFile, policy) {
		t.Errorf("edited file before the edit: should be equal")
	}
	if err := os.WriteFile(editedFile, []byte(policyDifferent), 0o600); err != nil {
		t.Fatalf("unable to edit file: %v", err)
	}
	if azureReleasePolicyEquivalent(editedFile, policy) {
		t.Errorf("edited file after the edit: should not be equal")
	}
	// A file that cannot be resolved to JSON is never equivalent.
	if azureReleasePolicyEquivalent(textFile, policy) || azureReleasePolicyEquivalent(missingFile, policy) {
		t.Errorf("unusable file: should not be equal")
	}

	// 10. Rotation state. enable_auto_rotation is rebuilt from the labels on every read. A configured
	// release_policy is kept only when it matches the label.
	labelResponse := func(label string) string {
		return `{"labels":{"job_config_id":"job-1","auto_rotate_key_source":"native","auto_rotate_key_type":"RSA",` +
			`"auto_rotate_key_size":2048,"auto_rotate_enable_key":true,"auto_rotate_release_policy":` + label + `}}`
	}
	drift := func(configured, response string) types.String {
		prior := &models.EnableAutoRotationTFSDK{ReleasePolicy: types.StringValue(configured)}
		rot := azureKeyRotationFromState(response, prior)
		if rot == nil {
			t.Fatalf("rotation state: got nil, want the block")
		}
		return rot.ReleasePolicy
	}
	// 10a. A file that matches the label is kept as the path.
	if got := drift(reorderedFile, labelResponse(policy)); got.ValueString() != reorderedFile {
		t.Errorf("drift, matching file: got %q, want the file path kept", got.ValueString())
	}
	// 10b. Inline JSON that matches the label is kept.
	if got := drift(policyReordered, labelResponse(policy)); got.ValueString() != policyReordered {
		t.Errorf("drift, matching JSON: got %q, want the configured JSON kept", got.ValueString())
	}
	// 10c. A label changed outside Terraform replaces a file path with the label JSON.
	if got := drift(policyFile, labelResponse(policyDifferent)); got.ValueString() != policyDifferent {
		t.Errorf("drift, changed label with a file: got %q, want the label JSON", got.ValueString())
	}
	// 10d. A label changed outside Terraform replaces inline JSON with the label JSON.
	if got := drift(policy, labelResponse(policyDifferent)); got.ValueString() != policyDifferent {
		t.Errorf("drift, changed label with JSON: got %q, want the label JSON", got.ValueString())
	}
	// 10e. A label that was removed gives null.
	if got := drift(policyFile, `{"labels":{"job_config_id":"job-1"}}`); !got.IsNull() {
		t.Errorf("drift, missing label: got %q, want null", got.ValueString())
	}
	// 10f. A file that was deleted is detected as drift because it cannot match the label.
	if got := drift(missingFile, labelResponse(policy)); got.ValueString() != policy {
		t.Errorf("drift, deleted file: got %q, want the label JSON", got.ValueString())
	}
	// 10g. A policy that is not in state is left alone.
	// A policy that is in the label but not in state is taken from the label.
	if rot := azureKeyRotationFromState(labelResponse(policy), &models.EnableAutoRotationTFSDK{ReleasePolicy: types.StringNull()}); rot == nil || rot.ReleasePolicy.ValueString() != policy {
		t.Errorf("state, policy only in the label: want the label JSON")
	}

	// 11. Other rotation fields are taken from the labels.
	rot := azureKeyRotationFromState(labelResponse(policy), nil)
	if rot == nil || rot.JobConfigID.ValueString() != "job-1" || rot.KeySource.ValueString() != "native" ||
		rot.KeyType.ValueString() != "RSA" || rot.KeySize.ValueInt64() != 2048 || !rot.EnableKey.ValueBool() {
		t.Errorf("state from labels: got %+v, want the label values", rot)
	}
	// 11a. A changed key_type label replaces the prior value.
	changed := strings.Replace(labelResponse(policy), `"RSA"`, `"EC"`, 1)
	if rot := azureKeyRotationFromState(changed, &models.EnableAutoRotationTFSDK{KeyType: types.StringValue("RSA")}); rot == nil || rot.KeyType.ValueString() != "EC" {
		t.Errorf("state, changed key_type label: want EC")
	}
	// 11b. Values that are not in the labels are null.
	sparse := `{"labels":{"job_config_id":"job-1","auto_rotate_key_source":"native","auto_rotate_key_type":"EC","auto_rotate_enable_key":true}}`
	if rot := azureKeyRotationFromState(sparse, &models.EnableAutoRotationTFSDK{KeySize: types.Int64Value(2048)}); rot == nil ||
		!rot.KeySize.IsNull() || !rot.ECName.IsNull() || !rot.ReleasePolicy.IsNull() {
		t.Errorf("state, sparse labels: key_size, ec_name and release_policy should be null")
	}
	// 11c. No job_config_id label means rotation is not enabled, so the block is nil.
	if rot := azureKeyRotationFromState(`{"labels":{}}`, &models.EnableAutoRotationTFSDK{JobConfigID: types.StringValue("job-1")}); rot != nil {
		t.Errorf("state, no rotation labels: want nil, got %+v", rot)
	}
	// 11d. Rotation disabled outside Terraform. Disabling clears the labels, so they may be null or absent.
	// A full block in state becomes nil, so the next plan shows the block being added back.
	fullPrior := &models.EnableAutoRotationTFSDK{
		JobConfigID:   types.StringValue("job-1"),
		KeySource:     types.StringValue("native"),
		KeyType:       types.StringValue("RSA"),
		KeySize:       types.Int64Value(2048),
		EnableKey:     types.BoolValue(true),
		ReleasePolicy: types.StringValue(policyFile),
	}
	for _, disabled := range []string{`{"labels":null}`, `{}`, `{"labels":{"job_config_id":""}}`} {
		if rot := azureKeyRotationFromState(disabled, fullPrior); rot != nil {
			t.Errorf("state, rotation disabled with response %s: want nil, got %+v", disabled, rot)
		}
	}

	// 12. A release policy file that is edited after it was applied is detected on the next read. The state
	// value is the file path while the file matches the label and becomes the label JSON once it does not.
	rotationFile := filepath.Join(dir, "rotation.json")
	if err := os.WriteFile(rotationFile, []byte(policy), 0o600); err != nil {
		t.Fatalf("unable to write rotation policy file: %v", err)
	}
	filePrior := &models.EnableAutoRotationTFSDK{ReleasePolicy: types.StringValue(rotationFile)}
	if rot := azureKeyRotationFromState(labelResponse(policy), filePrior); rot == nil || rot.ReleasePolicy.ValueString() != rotationFile {
		t.Errorf("state, unchanged file: want the file path kept")
	}
	if err := os.WriteFile(rotationFile, []byte(policyDifferent), 0o600); err != nil {
		t.Fatalf("unable to edit rotation policy file: %v", err)
	}
	if rot := azureKeyRotationFromState(labelResponse(policy), filePrior); rot == nil || rot.ReleasePolicy.ValueString() != policy {
		t.Errorf("state, edited file: want the label JSON so that the plan shows a change")
	}
	// Once the update has applied the new content to the label, the file path is kept again.
	if rot := azureKeyRotationFromState(labelResponse(policyDifferent), filePrior); rot == nil || rot.ReleasePolicy.ValueString() != rotationFile {
		t.Errorf("state, edited file after the update: want the file path kept")
	}
}
