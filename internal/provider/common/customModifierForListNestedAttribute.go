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
	// Only copy prior state when state is not null (i.e., an existing resource).
	// On create, state is null; leaving the plan as Unknown tells Terraform the
	// value will be determined after apply, avoiding a "null vs list" inconsistency.
	if req.PlanValue.IsUnknown() && !req.StateValue.IsNull() {
		resp.PlanValue = req.StateValue
	}
}

func NewListUseStateForUnknown() planmodifier.List {
	return ListUseStateForUnknown{}
}
