package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// azureReleasePolicyContent resolves a release_policy value to JSON text. The value is either the JSON
// itself or the path of a file that holds it. The API takes the JSON, never a file name, so the contents
// of the file are returned when the value is an existing file.
func azureReleasePolicyContent(value string) (string, error) {
	content, err := azureFileOrContent(value)
	if err != nil {
		return "", fmt.Errorf("unable to read release_policy file: %w", err)
	}
	return content, nil
}

// azureReleasePolicyObject resolves a release_policy value and parses it as a JSON object. An error
// diagnostic is added and false is returned if the file cannot be read or the content is not a JSON object.
func azureReleasePolicyObject(value string, attrPath path.Path, diags *diag.Diagnostics) (map[string]interface{}, bool) {
	content, err := azureReleasePolicyContent(value)
	if err != nil {
		diags.AddAttributeError(attrPath, "Invalid release policy", err.Error())
		return nil, false
	}
	var policy map[string]interface{}
	if err := json.Unmarshal([]byte(content), &policy); err != nil {
		// The content is the value itself unless the value is the path of an existing file.
		if content != value && strings.TrimSpace(value) != "" {
			diags.AddAttributeError(attrPath, "Invalid release policy",
				fmt.Sprintf("The file %q does not contain a valid JSON object.", strings.TrimSpace(value)))
			return nil, false
		}
		if !strings.HasPrefix(strings.TrimSpace(content), "{") {
			diags.AddAttributeError(attrPath, "Invalid release policy",
				fmt.Sprintf("release_policy is not a JSON object and no file was found at the path %q. "+
					"Check that the file exists and that the path is correct, or set release_policy to a JSON object.",
					strings.TrimSpace(value)))
			return nil, false
		}
		diags.AddAttributeError(attrPath, "Invalid release policy",
			"release_policy must be a valid JSON object or the path of a file that contains one.")
		return nil, false
	}
	return policy, true
}

// azureReleasePolicyEquivalent returns true if two release_policy values, each JSON or a file path,
// resolve to semantically equal JSON.
func azureReleasePolicyEquivalent(a, b string) bool {
	ca, errA := azureReleasePolicyContent(a)
	cb, errB := azureReleasePolicyContent(b)
	if errA != nil || errB != nil {
		return false
	}
	var ja, jb interface{}
	if json.Unmarshal([]byte(ca), &ja) != nil || json.Unmarshal([]byte(cb), &jb) != nil {
		return false
	}
	return reflect.DeepEqual(ja, jb)
}

type azureReleasePolicyValidator struct{}

// azureReleasePolicyJSONOrFile returns a validator that requires the value to be a JSON object or the
// path of a file that contains a JSON object. Null, unknown and empty values are accepted.
func azureReleasePolicyJSONOrFile() validator.String {
	return azureReleasePolicyValidator{}
}

func (v azureReleasePolicyValidator) Description(_ context.Context) string {
	return "value must be a JSON object or the path of a file that contains a JSON object"
}

func (v azureReleasePolicyValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v azureReleasePolicyValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.TrimSpace(req.ConfigValue.ValueString()) == "" {
		return
	}
	azureReleasePolicyObject(req.ConfigValue.ValueString(), req.Path, &resp.Diagnostics)
}

type azureReleasePolicyImmutableModifier struct{}

// azureReleasePolicyImmutable is like modifiers.ImmutableJSONString but each value may also be the path
// of a file. Values that resolve to equal JSON are treated as unchanged and the state value is kept.
func azureReleasePolicyImmutable() planmodifier.String {
	return azureReleasePolicyImmutableModifier{}
}

func (m azureReleasePolicyImmutableModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation. Equivalent JSON, or a file with equivalent JSON, is not treated as a change."
}

func (m azureReleasePolicyImmutableModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m azureReleasePolicyImmutableModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	if !req.StateValue.IsNull() && !req.StateValue.IsUnknown() &&
		azureReleasePolicyEquivalent(req.PlanValue.ValueString(), req.StateValue.ValueString()) {
		resp.PlanValue = req.StateValue
		return
	}
	modifiers.ImmutableString().PlanModifyString(ctx, req, resp)
}
