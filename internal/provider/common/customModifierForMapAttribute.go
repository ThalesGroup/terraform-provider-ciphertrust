package common

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UseStateForUnknown returns a plan modifier that copies the prior state value
// for a MapAttribute into the planned value if the planned value is unknown.
func NewMapUseStateForUnknown() planmodifier.Map {
	return MapUseStateForUnknown{}
}

type MapUseStateForUnknown struct{}

// Description returns a human-readable description of the plan modifier.
func (m MapUseStateForUnknown) Description(_ context.Context) string {
	return "If the planned value is unknown, use the prior state value."
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m MapUseStateForUnknown) MarkdownDescription(_ context.Context) string {
	return "If the planned value is unknown, use the prior state value."
}

// PlanModifyMap modifies the planned Map value based on the state.
func (m MapUseStateForUnknown) PlanModifyMap(ctx context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	// If the planned value is not unknown, do nothing
	if !req.PlanValue.IsUnknown() {
		return
	}

	// If there’s no prior state, set planned value to null (or handle as needed)
	if req.StateValue.IsNull() {
		resp.PlanValue = types.MapNull(req.PlanValue.ElementType(ctx))
		return
	}

	// Copy the prior state value to the planned value
	resp.PlanValue = req.StateValue
}
