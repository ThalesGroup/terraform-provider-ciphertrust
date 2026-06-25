package cckm

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// nullOrStateForUnknownObject is a plan modifier for Computed-only SingleNestedAttribute
// fields whose Go TFSDK type is a pointer (e.g. *MultiRegionConfigTFSDK). The Terraform
// Plugin Framework marks Computed-only attributes as unknown in the plan. This modifier
// resolves the unknown:
//   - New resource (null prior state): leaves the planned value as unknown so that
//     Terraform accepts whatever value (null or non-null) the provider returns after apply.
//   - Existing resource (known prior state): copies the prior state value to avoid
//     spurious "will be recomputed" diffs on this read-only nested object.
type nullOrStateForUnknownObject struct{}

// retainOrDefaultInt64 is a plan modifier for an Optional+Computed Int64 attribute that
// should default to a fixed value on first create, then retain its state value when the
// attribute is removed from config on subsequent updates.
//
// Behaviour:
//   - Config value present: use the configured value (no-op).
//   - Config value absent, state value present (update): retain the state value.
//   - Config value absent, state value absent (create): use the supplied default.
type retainOrDefaultInt64 struct {
	defaultVal int64
}

func (m retainOrDefaultInt64) Description(_ context.Context) string {
	return "Retains the prior state value when the attribute is removed from config; uses the default on first create."
}

func (m retainOrDefaultInt64) MarkdownDescription(_ context.Context) string {
	return "Retains the prior state value when the attribute is removed from config; uses the default on first create."
}

func (m retainOrDefaultInt64) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// Attribute is explicitly set in config - nothing to do.
	if !req.ConfigValue.IsNull() {
		return
	}
	// Attribute absent from config: retain prior state if available.
	if !req.StateValue.IsNull() && !req.StateValue.IsUnknown() {
		resp.PlanValue = req.StateValue
		return
	}
	// No prior state (first create): apply the default value.
	resp.PlanValue = types.Int64Value(m.defaultVal)
}

func (nullOrStateForUnknownObject) Description(_ context.Context) string {
	return "Use null for new resources; use prior state value for existing resources."
}

func (nullOrStateForUnknownObject) MarkdownDescription(_ context.Context) string {
	return "Use null for new resources; use prior state value for existing resources."
}

func (nullOrStateForUnknownObject) PlanModifyObject(_ context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	if !req.PlanValue.IsUnknown() {
		return
	}
	// New resource: state is null. Leave plan as unknown so Terraform accepts
	// whatever value (null or non-null) the provider returns after apply.
	// Returning null here would cause an "inconsistent result after apply" error
	// when the provider sets a non-null value (e.g. multi_region_configuration
	// for a multi-region key).
	if req.StateValue.IsNull() {
		return
	}
	// Existing resource: copy prior state to avoid spurious recompute diffs.
	resp.PlanValue = req.StateValue
}
