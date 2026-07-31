package cm

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// clearRejectStringModifier, clearRejectInt64Modifier, and clearRejectMapModifier
// block only the "clear a previously-set field by omitting it from config"
// direction — CM's PATCH endpoint leaves an omitted (or empty-string/empty-object)
// key unchanged server-side rather than clearing it, so silently accepting the
// clear would never converge.
//
// Unlike modifiers.UseStateWhenClearingString()/Map(), these do NOT substitute
// the prior state value back into the plan: for a plain Optional (non-Computed)
// attribute, Terraform requires the planned value to equal the config value, so
// silently diverging from config produces "Provider produced invalid plan" at
// plan time, and if the attribute were also marked Computed to permit that
// divergence, Create()/Read() would then need to always resolve a concrete value
// post-apply — a much larger change to this resource's existing "leave
// permanently null if never configured" convention. Instead, these modifiers
// surface the clear attempt as an explicit AddError (mirroring the working
// `meta` field's MergePatchObject behavior) and leave PlanValue untouched, so
// the plan simply fails with a clear diagnostic instead of ever reaching the
// invalid-plan or invalid-apply-result checks.
//
// Adding or changing the field to a new non-empty value is unaffected — only
// the omission/empty-clear direction is blocked.

type clearRejectStringModifier struct {
	FieldName string
}

func (m clearRejectStringModifier) Description(_ context.Context) string {
	return fmt.Sprintf("'%s' cannot be cleared once set — CM's PATCH endpoint does not honour empty-string/omitted requests for this field.", m.FieldName)
}

func (m clearRejectStringModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m clearRejectStringModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() {
		return // create path
	}
	if !req.PlanValue.IsNull() && req.PlanValue.ValueString() != "" {
		return // explicit non-empty value — not a clear attempt
	}
	if req.StateValue.IsNull() || req.StateValue.ValueString() == "" {
		return // nothing set to clear
	}
	resp.Diagnostics.AddError(
		"Cannot Clear Field After Creation",
		fmt.Sprintf(
			"The '%s' field was set and cannot be cleared by omitting it from config. "+
				"CM's merge-PATCH leaves omitted fields unchanged on the server, so removing "+
				"it here would never converge. Restore the previous value, or destroy and "+
				"recreate the resource.",
			m.FieldName,
		),
	)
}

type clearRejectInt64Modifier struct {
	FieldName string
}

func (m clearRejectInt64Modifier) Description(_ context.Context) string {
	return fmt.Sprintf("'%s' cannot be cleared once set — CM's PATCH endpoint does not honour omitted requests for this field.", m.FieldName)
}

func (m clearRejectInt64Modifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m clearRejectInt64Modifier) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	if req.State.Raw.IsNull() {
		return // create path
	}
	if !req.PlanValue.IsNull() {
		return // explicit value, including 0 — not a clear attempt
	}
	if req.StateValue.IsNull() {
		return // nothing set to clear
	}
	resp.Diagnostics.AddError(
		"Cannot Clear Field After Creation",
		fmt.Sprintf(
			"The '%s' field was set and cannot be cleared by omitting it from config. "+
				"CM's merge-PATCH leaves omitted fields unchanged on the server, so removing "+
				"it here would never converge. Restore the previous value, or destroy and "+
				"recreate the resource.",
			m.FieldName,
		),
	)
}

type clearRejectMapModifier struct {
	FieldName string
}

func (m clearRejectMapModifier) Description(_ context.Context) string {
	return fmt.Sprintf("'%s' cannot be cleared once set — CM's PATCH endpoint does not honour empty-object/omitted requests for this field.", m.FieldName)
}

func (m clearRejectMapModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m clearRejectMapModifier) PlanModifyMap(_ context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	if req.State.Raw.IsNull() {
		return // create path
	}
	if !req.PlanValue.IsNull() && !req.PlanValue.IsUnknown() && len(req.PlanValue.Elements()) > 0 {
		return // explicit non-empty map — not a clear attempt
	}
	if req.StateValue.IsNull() || len(req.StateValue.Elements()) == 0 {
		return // nothing set to clear
	}
	resp.Diagnostics.AddError(
		"Cannot Clear Field After Creation",
		fmt.Sprintf(
			"The '%s' field was set and cannot be cleared by omitting it from config. "+
				"CM's merge-PATCH leaves omitted fields unchanged on the server, so removing "+
				"it here would never converge. Restore the previous value, or destroy and "+
				"recreate the resource.",
			m.FieldName,
		),
	)
}
