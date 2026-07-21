package modifiers

// UseStateWhenClearingString and UseStateWhenClearingMap address a CM API
// limitation where certain fields (description, meta) are silently ignored when
// sent as empty string / empty object in a PATCH request. CM returns HTTP 200
// but does not store the change, so the prior value persists on subsequent GETs.
//
// Applying these modifiers prevents the perpetual-diff cycle that would otherwise
// result: without them, a user who removes `description` from their HCL would see
// `terraform plan` perpetually propose the same no-op change.
//
// Modifier behaviour:
//   - On resource creation (no prior state): passes through — allows any value.
//   - On update, if the planned value is empty/null AND state holds a non-empty
//     value: replaces the plan value with the state value, suppressing the diff.
//   - Otherwise (value is being set to a real non-empty value, or both sides are
//     empty): passes through unchanged.

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// UseStateWhenClearingString returns a String plan modifier that substitutes the
// prior state value when the plan tries to clear a string field to "" or null.
// Use this on string attributes that CM cannot clear once set (e.g. description).
func UseStateWhenClearingString() planmodifier.String {
	return useStateWhenClearingStringModifier{}
}

type useStateWhenClearingStringModifier struct{}

func (m useStateWhenClearingStringModifier) Description(_ context.Context) string {
	return "Preserves the prior state value when the planned value is empty or null, " +
		"because CM does not honour empty-string PATCH requests for this field. " +
		"Once set, this field cannot be cleared back to empty via Terraform."
}

func (m useStateWhenClearingStringModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m useStateWhenClearingStringModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Brand-new resource — no prior state, nothing to preserve.
	if req.State.Raw.IsNull() {
		return
	}
	// Plan value is not empty/null — user is setting a real value, pass through.
	if !req.PlanValue.IsNull() && req.PlanValue.ValueString() != "" {
		return
	}
	// State has no value to preserve — pass through.
	if req.StateValue.IsNull() || req.StateValue.ValueString() == "" {
		return
	}
	// Plan is trying to clear a non-empty state value. CM cannot honour this,
	// so substitute the state value to suppress the perpetual diff.
	resp.Diagnostics.AddAttributeWarning(
		req.Path,
		"Clear ignored by CipherTrust Manager",
		"CM does not support clearing this field once set; the previous value has been retained.",
	)
	resp.PlanValue = req.StateValue
}

// UseStateWhenClearingMap returns a Map plan modifier that substitutes the prior
// state value when the plan tries to clear a map field to null or an empty map.
// Use this on map attributes that CM cannot clear once set (e.g. meta).
func UseStateWhenClearingMap() planmodifier.Map {
	return useStateWhenClearingMapModifier{}
}

type useStateWhenClearingMapModifier struct{}

func (m useStateWhenClearingMapModifier) Description(_ context.Context) string {
	return "Preserves the prior state value when the planned value is null or empty, " +
		"because CM does not honour empty-object PATCH requests for this field. " +
		"Once set, this field cannot be cleared back to empty via Terraform."
}

func (m useStateWhenClearingMapModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m useStateWhenClearingMapModifier) PlanModifyMap(_ context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	// Brand-new resource — no prior state, nothing to preserve.
	if req.State.Raw.IsNull() {
		return
	}
	// Plan value is not empty/null — user is setting real entries, pass through.
	if !req.PlanValue.IsNull() && !req.PlanValue.IsUnknown() && len(req.PlanValue.Elements()) > 0 {
		return
	}
	// State is also empty/null — nothing to preserve, pass through.
	if req.StateValue.IsNull() || len(req.StateValue.Elements()) == 0 {
		return
	}
	// Plan is trying to clear a non-empty state map. CM cannot honour this,
	// so substitute the state value to suppress the perpetual diff.
	resp.Diagnostics.AddAttributeWarning(
		req.Path,
		"Clear ignored by CipherTrust Manager",
		"CM does not support clearing this field once set; the previous value has been retained.",
	)
	resp.PlanValue = req.StateValue
}

// UseStateForNullOrUnknownString returns a String plan modifier that substitutes the
// prior state value when the planned value is null or unknown.
func UseStateForNullOrUnknownString() planmodifier.String {
	return useStateForNullOrUnknownStringModifier{}
}

type useStateForNullOrUnknownStringModifier struct{}

func (m useStateForNullOrUnknownStringModifier) Description(_ context.Context) string {
	return "Preserves the prior state value when the planned value is null or unknown."
}

func (m useStateForNullOrUnknownStringModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m useStateForNullOrUnknownStringModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Brand-new resource — no prior state, nothing to preserve.
	if req.State.Raw.IsNull() {
		return
	}
	// If the planned value is Null or Unknown, copy the state value to the plan.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		resp.PlanValue = req.StateValue
	}
}

// UseStateForNullOrUnknownBool returns a Bool plan modifier that substitutes the
// prior state value when the planned value is null or unknown.
func UseStateForNullOrUnknownBool() planmodifier.Bool {
	return useStateForNullOrUnknownBoolModifier{}
}

type useStateForNullOrUnknownBoolModifier struct{}

func (m useStateForNullOrUnknownBoolModifier) Description(_ context.Context) string {
	return "Preserves the prior state value when the planned value is null or unknown."
}

func (m useStateForNullOrUnknownBoolModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m useStateForNullOrUnknownBoolModifier) PlanModifyBool(_ context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Brand-new resource — no prior state, nothing to preserve.
	if req.State.Raw.IsNull() {
		return
	}
	// If the planned value is Null or Unknown, copy the state value to the plan.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		resp.PlanValue = req.StateValue
	}
}
