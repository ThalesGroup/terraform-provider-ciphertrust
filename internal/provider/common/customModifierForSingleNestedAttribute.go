package common

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// ObjectUseStateForUnknown is a custom plan modifier for SingleNestedAttribute.
type ObjectUseStateForUnknown struct{}

func (m ObjectUseStateForUnknown) Description(ctx context.Context) string {
	return "Use prior state value if unknown during planning"
}

func (m ObjectUseStateForUnknown) MarkdownDescription(ctx context.Context) string {
	return "Use prior state value if unknown during planning"
}

func (m ObjectUseStateForUnknown) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	// If the plan value is unknown, use the state value.
	if req.PlanValue.IsUnknown() {
		resp.PlanValue = req.StateValue
	}
}

func NewObjectUseStateForUnknown() planmodifier.Object {
	return ObjectUseStateForUnknown{}
}
