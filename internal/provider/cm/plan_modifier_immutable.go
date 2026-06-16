package cm

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

type immutableStringModifier struct{}

func (m immutableStringModifier) Description(_ context.Context) string {
	return "Prevents changes to this attribute after resource creation."
}

func (m immutableStringModifier) MarkdownDescription(_ context.Context) string {
	return "Prevents changes to this attribute after resource creation."
}

func (m immutableStringModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.StateValue.IsNull() && !req.StateValue.IsUnknown() && !req.PlanValue.Equal(req.StateValue) {
		resp.Diagnostics.AddError(
			"Attribute 'name' cannot be changed after creation",
			"The 'name' field is immutable and is used as the resource identifier on CipherTrust Manager. To rename, destroy the existing resource and create a new one.",
		)
	}
}

// ImmutableString returns a plan modifier that prevents changes to an attribute after creation.
func ImmutableString() planmodifier.String {
	return immutableStringModifier{}
}
