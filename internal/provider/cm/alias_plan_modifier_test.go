package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// aliasElemType is the attr.Type for one KeyAliasTFSDK element, matching the
// `aliases` NestedObject schema (alias, index, type — all strings).
var aliasElemType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"alias": types.StringType,
	"index": types.StringType,
	"type":  types.StringType,
}}

func aliasListValue(t *testing.T, aliases []KeyAliasTFSDK) types.List {
	t.Helper()
	list, diags := types.ListValueFrom(context.Background(), aliasElemType, aliases)
	if diags.HasError() {
		t.Fatalf("failed to build test alias list: %v", diags)
	}
	return list
}

// nonNullAliasRawState returns a tfsdk.State whose Raw is non-null, simulating
// an existing resource that was previously created.
func nonNullAliasRawState() tfsdk.State {
	return tfsdk.State{
		Raw: tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{},
		}, map[string]tftypes.Value{}),
	}
}

// Test_CM_AliasListIndexModifier verifies aliasListIndexModifier correlates plan
// aliases to state aliases by name (not position), fixing the "index: was null,
// but now ..." consistency crash when a new alias is appended to an existing key.
func Test_CM_AliasListIndexModifier(t *testing.T) {
	mod := aliasListIndexModifier{}

	// nonNullPlan simulates an in-progress plan (not a destroy). The Plan.Raw must be
	// explicitly non-null so the destroy guard (req.Plan.Raw.IsNull()) does not fire:
	// tftypes.Value{}'s zero value has a nil inner value, which IsNull() treats as null.
	nonNullPlan := tfsdk.Plan{Raw: tftypes.NewValue(
		tftypes.Object{AttributeTypes: map[string]tftypes.Type{}},
		map[string]tftypes.Value{},
	)}

	run := func(stateRaw tfsdk.State, stateVal, planVal types.List) planmodifier.ListResponse {
		req := planmodifier.ListRequest{
			State:      stateRaw,
			Plan:       nonNullPlan,
			StateValue: stateVal,
			PlanValue:  planVal,
		}
		resp := planmodifier.ListResponse{PlanValue: planVal}
		mod.PlanModifyList(context.Background(), req, &resp)
		return resp
	}

	t.Run("brand-new resource: plan passes through unchanged", func(t *testing.T) {
		plan := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringUnknown(), Type: types.StringValue("string")},
		})
		resp := run(tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil)}, types.ListNull(aliasElemType), plan)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error on create path: %v", resp.Diagnostics)
		}
		if !resp.PlanValue.Equal(plan) {
			t.Errorf("expected plan value to pass through unchanged, got %v", resp.PlanValue)
		}
	})

	t.Run("existing alias matched by name reuses state index, even if reordered", func(t *testing.T) {
		state := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringValue("0"), Type: types.StringValue("string")},
			{Alias: types.StringValue("a2"), Index: types.StringValue("1"), Type: types.StringValue("string")},
		})
		// Reordered in plan: a2 first, a1 second.
		plan := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a2"), Index: types.StringUnknown(), Type: types.StringValue("string")},
			{Alias: types.StringValue("a1"), Index: types.StringUnknown(), Type: types.StringValue("string")},
		})
		resp := run(nonNullAliasRawState(), state, plan)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics)
		}
		var got []KeyAliasTFSDK
		if diags := resp.PlanValue.ElementsAs(context.Background(), &got, false); diags.HasError() {
			t.Fatalf("failed to read back plan value: %v", diags)
		}
		if got[0].Alias.ValueString() != "a2" || got[0].Index.ValueString() != "1" {
			t.Errorf("expected a2 to keep index 1, got %+v", got[0])
		}
		if got[1].Alias.ValueString() != "a1" || got[1].Index.ValueString() != "0" {
			t.Errorf("expected a1 to keep index 0, got %+v", got[1])
		}
	})

	t.Run("new alias not present in state becomes Unknown, not null", func(t *testing.T) {
		state := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		})
		plan := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringUnknown(), Type: types.StringValue("string")},
			{Alias: types.StringValue("a2-new"), Index: types.StringUnknown(), Type: types.StringValue("string")},
		})
		resp := run(nonNullAliasRawState(), state, plan)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics)
		}
		var got []KeyAliasTFSDK
		if diags := resp.PlanValue.ElementsAs(context.Background(), &got, false); diags.HasError() {
			t.Fatalf("failed to read back plan value: %v", diags)
		}
		if got[0].Alias.ValueString() != "a1" || got[0].Index.ValueString() != "0" {
			t.Errorf("expected a1 to keep index 0, got %+v", got[0])
		}
		if got[1].Alias.ValueString() != "a2-new" || !got[1].Index.IsUnknown() {
			t.Errorf("expected a2-new's index to be Unknown, got %+v (IsUnknown=%v)", got[1], got[1].Index.IsUnknown())
		}
	})

	t.Run("destroy plan: modifier returns early, no index correlation attempted", func(t *testing.T) {
		state := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		})
		destroyPlan := tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil)}
		req := planmodifier.ListRequest{
			State:      nonNullAliasRawState(),
			Plan:       destroyPlan,
			StateValue: state,
			PlanValue:  types.ListNull(aliasElemType),
		}
		resp := planmodifier.ListResponse{PlanValue: types.ListNull(aliasElemType)}
		mod.PlanModifyList(context.Background(), req, &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("destroy plan must not produce errors: %v", resp.Diagnostics)
		}
	})

	t.Run("empty plan list is a no-op", func(t *testing.T) {
		state := aliasListValue(t, []KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		})
		plan := aliasListValue(t, []KeyAliasTFSDK{})
		resp := run(nonNullAliasRawState(), state, plan)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics)
		}
		if !resp.PlanValue.Equal(plan) {
			t.Errorf("expected empty plan to pass through unchanged, got %v", resp.PlanValue)
		}
	})
}
