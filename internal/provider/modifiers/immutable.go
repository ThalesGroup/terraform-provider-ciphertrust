package modifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// ImmutableString returns a plan modifier that prevents a string attribute from
// changing after the resource is created. A plan-time diagnostic error is emitted
// if the value differs from state, preventing destroy+recreate.
func ImmutableString() planmodifier.String {
	return immutableStringModifier{}
}

type immutableStringModifier struct{}

func (m immutableStringModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableStringModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableStringModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		fmt.Sprintf(
			"This attribute cannot be changed after creation (old: %q, new: %q). "+
				"To change this attribute, destroy and recreate the resource.",
			req.StateValue.ValueString(),
			req.PlanValue.ValueString(),
		),
	)
	resp.PlanValue = req.StateValue
}

// ImmutableInt64 returns a plan modifier that prevents an int64 attribute from
// changing after the resource is created.
func ImmutableInt64() planmodifier.Int64 {
	return immutableInt64Modifier{}
}

type immutableInt64Modifier struct{}

func (m immutableInt64Modifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableInt64Modifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableInt64Modifier) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		fmt.Sprintf(
			"This attribute cannot be changed after creation (old: %d, new: %d). "+
				"To change this attribute, destroy and recreate the resource.",
			req.StateValue.ValueInt64(),
			req.PlanValue.ValueInt64(),
		),
	)
	resp.PlanValue = req.StateValue
}

// ImmutableBool returns a plan modifier that prevents a bool attribute from
// changing after the resource is created.
func ImmutableBool() planmodifier.Bool {
	return immutableBoolModifier{}
}

type immutableBoolModifier struct{}

func (m immutableBoolModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableBoolModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableBoolModifier) PlanModifyBool(_ context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		fmt.Sprintf(
			"This attribute cannot be changed after creation (old: %v, new: %v). "+
				"To change this attribute, destroy and recreate the resource.",
			req.StateValue.ValueBool(),
			req.PlanValue.ValueBool(),
		),
	)
	resp.PlanValue = req.StateValue
}

// ImmutableList returns a plan modifier that prevents a list attribute from
// changing after the resource is created.
func ImmutableList() planmodifier.List {
	return immutableListModifier{}
}

type immutableListModifier struct{}

func (m immutableListModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableListModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableListModifier) PlanModifyList(_ context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This list attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}
