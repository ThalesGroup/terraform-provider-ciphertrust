package modifiers_test

import (
	"context"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// nullResourceRaw is the raw value the framework passes when a resource has no prior
// state (brand-new create) or when the plan tears it down (destroy).
var nullResourceRaw = tftypes.NewValue(tftypes.Object{}, nil)

// nonNullResourceRaw represents an existing resource in state/plan (update path).
var nonNullResourceRaw = tftypes.NewValue(
	tftypes.Object{AttributeTypes: map[string]tftypes.Type{"x": tftypes.String}},
	map[string]tftypes.Value{"x": tftypes.NewValue(tftypes.String, "v")},
)

func nullState() tfsdk.State   { return tfsdk.State{Raw: nullResourceRaw} }
func liveState() tfsdk.State   { return tfsdk.State{Raw: nonNullResourceRaw} }
func destroyPlan() tfsdk.Plan  { return tfsdk.Plan{Raw: nullResourceRaw} }
func updatePlan() tfsdk.Plan   { return tfsdk.Plan{Raw: nonNullResourceRaw} }

// TestImmutableString verifies ImmutableString lifecycle semantics.
func TestImmutableString(t *testing.T) {
	mod := modifiers.ImmutableString()
	ctx := context.Background()

	old := types.StringValue("original")
	changed := types.StringValue("changed")

	cases := []struct {
		name      string
		state     tfsdk.State
		plan      tfsdk.Plan
		stateVal  types.String
		planVal   types.String
		wantError bool
	}{
		{
			name: "create (null state) — allow any value",
			state: nullState(), plan: updatePlan(),
			stateVal: types.StringNull(), planVal: changed, wantError: false,
		},
		{
			name: "destroy with matching config — allow",
			state: liveState(), plan: destroyPlan(),
			stateVal: old, planVal: old, wantError: false,
		},
		{
			name: "destroy with drifted config — allow (TFIN-552 regression)",
			state: liveState(), plan: destroyPlan(),
			stateVal: old, planVal: changed, wantError: false,
		},
		{
			name: "update no-change — allow",
			state: liveState(), plan: updatePlan(),
			stateVal: old, planVal: old, wantError: false,
		},
		{
			name: "update changed — block",
			state: liveState(), plan: updatePlan(),
			stateVal: old, planVal: changed, wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.StringRequest{
				State: tc.state, Plan: tc.plan,
				StateValue: tc.stateVal, PlanValue: tc.planVal,
			}
			resp := &planmodifier.StringResponse{PlanValue: tc.planVal}
			mod.PlanModifyString(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

// TestImmutableInt64 verifies ImmutableInt64 lifecycle semantics.
func TestImmutableInt64(t *testing.T) {
	mod := modifiers.ImmutableInt64()
	ctx := context.Background()

	old := types.Int64Value(1)
	changed := types.Int64Value(2)

	cases := []struct {
		name      string
		state     tfsdk.State
		plan      tfsdk.Plan
		stateVal  types.Int64
		planVal   types.Int64
		wantError bool
	}{
		{"create — allow", nullState(), updatePlan(), types.Int64Null(), changed, false},
		{"destroy drifted — allow (TFIN-552)", liveState(), destroyPlan(), old, changed, false},
		{"update no-change — allow", liveState(), updatePlan(), old, old, false},
		{"update changed — block", liveState(), updatePlan(), old, changed, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.Int64Request{
				State: tc.state, Plan: tc.plan,
				StateValue: tc.stateVal, PlanValue: tc.planVal,
			}
			resp := &planmodifier.Int64Response{PlanValue: tc.planVal}
			mod.PlanModifyInt64(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

// TestImmutableBool verifies ImmutableBool lifecycle semantics.
func TestImmutableBool(t *testing.T) {
	mod := modifiers.ImmutableBool()
	ctx := context.Background()

	old := types.BoolValue(true)
	changed := types.BoolValue(false)

	cases := []struct {
		name      string
		state     tfsdk.State
		plan      tfsdk.Plan
		stateVal  types.Bool
		planVal   types.Bool
		wantError bool
	}{
		{"create — allow", nullState(), updatePlan(), types.BoolNull(), changed, false},
		{"destroy drifted — allow (TFIN-552)", liveState(), destroyPlan(), old, changed, false},
		{"update no-change — allow", liveState(), updatePlan(), old, old, false},
		{"update changed — block", liveState(), updatePlan(), old, changed, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.BoolRequest{
				State: tc.state, Plan: tc.plan,
				StateValue: tc.stateVal, PlanValue: tc.planVal,
			}
			resp := &planmodifier.BoolResponse{PlanValue: tc.planVal}
			mod.PlanModifyBool(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

// TestImmutableList verifies ImmutableList lifecycle semantics.
func TestImmutableList(t *testing.T) {
	mod := modifiers.ImmutableList()
	ctx := context.Background()

	old, _ := types.ListValue(types.StringType, []attr.Value{types.StringValue("a")})
	changed, _ := types.ListValue(types.StringType, []attr.Value{types.StringValue("b")})

	cases := []struct {
		name      string
		state     tfsdk.State
		plan      tfsdk.Plan
		stateVal  types.List
		planVal   types.List
		wantError bool
	}{
		{"create — allow", nullState(), updatePlan(), types.ListNull(types.StringType), changed, false},
		{"destroy drifted — allow (TFIN-552)", liveState(), destroyPlan(), old, changed, false},
		{"update no-change — allow", liveState(), updatePlan(), old, old, false},
		{"update changed — block", liveState(), updatePlan(), old, changed, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.ListRequest{
				State: tc.state, Plan: tc.plan,
				StateValue: tc.stateVal, PlanValue: tc.planVal,
			}
			resp := &planmodifier.ListResponse{PlanValue: tc.planVal}
			mod.PlanModifyList(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

// TestImmutableMap verifies ImmutableMap lifecycle semantics.
func TestImmutableMap(t *testing.T) {
	mod := modifiers.ImmutableMap()
	ctx := context.Background()

	old, _ := types.MapValue(types.StringType, map[string]attr.Value{"k": types.StringValue("v1")})
	changed, _ := types.MapValue(types.StringType, map[string]attr.Value{"k": types.StringValue("v2")})

	cases := []struct {
		name      string
		state     tfsdk.State
		plan      tfsdk.Plan
		stateVal  types.Map
		planVal   types.Map
		wantError bool
	}{
		{"create — allow", nullState(), updatePlan(), types.MapNull(types.StringType), changed, false},
		{"destroy drifted — allow (TFIN-552)", liveState(), destroyPlan(), old, changed, false},
		{"update no-change — allow", liveState(), updatePlan(), old, old, false},
		{"update changed — block", liveState(), updatePlan(), old, changed, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.MapRequest{
				State: tc.state, Plan: tc.plan,
				StateValue: tc.stateVal, PlanValue: tc.planVal,
			}
			resp := &planmodifier.MapResponse{PlanValue: tc.planVal}
			mod.PlanModifyMap(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

// TestImmutableObject verifies ImmutableObject lifecycle semantics.
func TestImmutableObject(t *testing.T) {
	mod := modifiers.ImmutableObject()
	ctx := context.Background()

	attrTypes := map[string]attr.Type{"f": types.StringType}
	old, _ := types.ObjectValue(attrTypes, map[string]attr.Value{"f": types.StringValue("old")})
	changed, _ := types.ObjectValue(attrTypes, map[string]attr.Value{"f": types.StringValue("new")})

	cases := []struct {
		name      string
		plan      tfsdk.Plan
		stateVal  types.Object
		planVal   types.Object
		wantError bool
	}{
		{"create (null stateVal) — allow", updatePlan(), types.ObjectNull(attrTypes), changed, false},
		{"destroy drifted — allow (TFIN-552)", destroyPlan(), old, changed, false},
		{"update no-change — allow", updatePlan(), old, old, false},
		{"update changed — block", updatePlan(), old, changed, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.ObjectRequest{
				Plan:       tc.plan,
				StateValue: tc.stateVal,
				PlanValue:  tc.planVal,
			}
			resp := &planmodifier.ObjectResponse{PlanValue: tc.planVal}
			mod.PlanModifyObject(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

// TestImmutableObjectExceptWriteOnly verifies that changes to a named write-only child
// attribute are ignored when computing immutability, while changes to any other child
// attribute still block the plan. This is the fix for the class of bug where a WriteOnly
// leaf inside an otherwise-immutable object always differs from its always-null state
// value, misfiring on every plan (see cm_key's hkdf_create_parameters/wrap_hkdf.salt).
func TestImmutableObjectExceptWriteOnly(t *testing.T) {
	mod := modifiers.ImmutableObjectExceptWriteOnly("salt")
	ctx := context.Background()

	attrTypes := map[string]attr.Type{"info": types.StringType, "salt": types.StringType}
	old, _ := types.ObjectValue(attrTypes, map[string]attr.Value{"info": types.StringValue("i"), "salt": types.StringNull()})
	saltChanged, _ := types.ObjectValue(attrTypes, map[string]attr.Value{"info": types.StringValue("i"), "salt": types.StringValue("real-salt-value")})
	infoChanged, _ := types.ObjectValue(attrTypes, map[string]attr.Value{"info": types.StringValue("changed"), "salt": types.StringNull()})

	cases := []struct {
		name      string
		plan      tfsdk.Plan
		stateVal  types.Object
		planVal   types.Object
		wantError bool
	}{
		{"create (null stateVal) — allow", updatePlan(), types.ObjectNull(attrTypes), saltChanged, false},
		{"destroy drifted — allow (TFIN-552)", destroyPlan(), old, saltChanged, false},
		{"update no-change — allow", updatePlan(), old, old, false},
		{"update salt only (write-only leaf) — allow, matches WriteOnly plan-nulling behavior", updatePlan(), old, saltChanged, false},
		{"update non-write-only field changed — block", updatePlan(), old, infoChanged, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := planmodifier.ObjectRequest{
				Plan:       tc.plan,
				StateValue: tc.stateVal,
				PlanValue:  tc.planVal,
			}
			resp := &planmodifier.ObjectResponse{PlanValue: tc.planVal}
			mod.PlanModifyObject(ctx, req, resp)
			assertError(t, resp.Diagnostics.HasError(), tc.wantError)
		})
	}
}

func assertError(t *testing.T, got, want bool) {
	t.Helper()
	if want && !got {
		t.Error("expected a diagnostic error, got none")
	}
	if !want && got {
		t.Error("unexpected diagnostic error")
	}
}
