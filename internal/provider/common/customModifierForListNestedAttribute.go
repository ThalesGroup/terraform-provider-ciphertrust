package common

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// ListUseStateForUnknown is a custom plan modifier for SingleNestedAttribute.
type ListUseStateForUnknown struct{}

func (m ListUseStateForUnknown) Description(ctx context.Context) string {
	return "Use prior state value if unknown during planning"
}

func (m ListUseStateForUnknown) MarkdownDescription(ctx context.Context) string {
	return "Use prior state value if unknown during planning"
}

func (m ListUseStateForUnknown) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	// If the plan value is unknown, use the state value.
	if req.PlanValue.IsUnknown() {
		resp.PlanValue = req.StateValue
	}
}

func NewListUseStateForUnknown() planmodifier.List {
	return ListUseStateForUnknown{}
}
