// Package modifiers provides shared Terraform plan modifiers for the
// CipherTrust provider. ImmutableString, ImmutableInt64, ImmutableBool,
// ImmutableList, ImmutableMap, and ImmutableObject each enforce that a
// given schema attribute cannot change after resource creation, emitting
// a plan-time diagnostic error so no API call is made and no
// destroy+recreate occurs.
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
	// If the full prior resource state is null, this is a brand-new resource being
	// created for the first time — allow any value. We use req.State.Raw.IsNull()
	// rather than req.StateValue.IsNull() so that we correctly reject the case where
	// an Optional field was omitted on create (StateValue is null but State is not —
	// i.e. the resource already exists) and the user tries to add it on a subsequent
	// plan, which must be blocked as an immutable change.
	if req.State.Raw.IsNull() {
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
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	// Unknown plan value: comes from another resource's output, not a user change.
	if req.PlanValue.IsUnknown() {
		return
	}
	// No change — allow.
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
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	// Unknown plan value: comes from another resource's output, not yet known at plan
	// time. This is not a user-initiated change away from the existing value.
	if req.PlanValue.IsUnknown() {
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
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
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

// ImmutableMap returns a Map plan modifier that prevents in-place changes
// to a map attribute after resource creation. Any attempt to change the
// value after creation results in a plan-time error directing the user to
// destroy and recreate the resource.
func ImmutableMap() planmodifier.Map {
	return immutableMapModifier{}
}

type immutableMapModifier struct{}

func (m immutableMapModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableMapModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableMapModifier) PlanModifyMap(_ context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This map attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}

// ImmutableObject returns an Object plan modifier that prevents in-place changes
// to an object attribute after resource creation.
func ImmutableObject() planmodifier.Object {
	return immutableObjectModifier{}
}

type immutableObjectModifier struct{}

func (m immutableObjectModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableObjectModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

// PlanModifyObject fires an error when a non-null state value is changed.
// The IsUnknown() early-return prevents false errors when plan sub-attributes
// are Unknown (e.g. populated by UseStateForUnknown() on nested attributes).
func (m immutableObjectModifier) PlanModifyObject(_ context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This object attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}
