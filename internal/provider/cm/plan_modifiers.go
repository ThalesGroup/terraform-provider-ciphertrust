package cm

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// NameImmutableModifier is a plan modifier that prevents the 'name' field from
// being changed after resource creation. It produces a clear, actionable error
// at plan time so the user is informed before any API call is made.
type NameImmutableModifier struct{}

func (m NameImmutableModifier) Description(_ context.Context) string {
	return "Name is immutable after creation."
}

func (m NameImmutableModifier) MarkdownDescription(_ context.Context) string {
	return "Name is immutable after creation."
}

func (m NameImmutableModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Name cannot be changed",
		fmt.Sprintf(
			"The 'name' field is immutable after creation. "+
				"Current name on CipherTrust Manager: %q. "+
				"To use a different name, remove this resource from Terraform state "+
				"(terraform state rm) and import or recreate it with the desired name.",
			req.StateValue.ValueString(),
		),
	)
}

// StringImmutableModifier is a generic plan modifier that prevents any string
// field from being changed after resource creation. Use FieldName to produce a
// field-specific error message.
type StringImmutableModifier struct {
	FieldName string
}

func (m StringImmutableModifier) Description(_ context.Context) string {
	return fmt.Sprintf("'%s' is immutable after creation.", m.FieldName)
}

func (m StringImmutableModifier) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("`%s` is immutable after creation.", m.FieldName)
}

func (m StringImmutableModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Allow setting on create (state is null) or when the value is unchanged.
	if req.StateValue.IsNull() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		fmt.Sprintf("'%s' cannot be changed", m.FieldName),
		fmt.Sprintf(
			"The '%s' field is immutable after creation. "+
				"Current value on CipherTrust Manager: %q. "+
				"To use a different value, remove this resource from Terraform state "+
				"(terraform state rm) and import or recreate it with the desired value.",
			m.FieldName,
			req.StateValue.ValueString(),
		),
	)
}

// Int64ImmutableModifier is a generic plan modifier that prevents any int64
// field from being changed after resource creation.
type Int64ImmutableModifier struct {
	FieldName string
}

func (m Int64ImmutableModifier) Description(_ context.Context) string {
	return fmt.Sprintf("'%s' is immutable after creation.", m.FieldName)
}

func (m Int64ImmutableModifier) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("`%s` is immutable after creation.", m.FieldName)
}

func (m Int64ImmutableModifier) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// Allow setting on create (state is null) or when the value is unchanged.
	if req.StateValue.IsNull() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		fmt.Sprintf("'%s' cannot be changed", m.FieldName),
		fmt.Sprintf(
			"The '%s' field is immutable after creation. "+
				"Current value on CipherTrust Manager: %d. "+
				"To use a different value, remove this resource from Terraform state "+
				"(terraform state rm) and import or recreate it with the desired value.",
			m.FieldName,
			req.StateValue.ValueInt64(),
		),
	)
}
