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

func Test_CM_ClearRejectStringModifier(t *testing.T) {
	mod := clearRejectStringModifier{FieldName: "description"}

	run := func(stateRaw tfsdk.State, stateVal, planVal types.String) planmodifier.StringResponse {
		req := planmodifier.StringRequest{State: stateRaw, StateValue: stateVal, PlanValue: planVal}
		resp := planmodifier.StringResponse{PlanValue: planVal}
		mod.PlanModifyString(context.Background(), req, &resp)
		return resp
	}

	t.Run("brand-new resource: passes through, no error", func(t *testing.T) {
		resp := run(tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil)}, types.StringNull(), types.StringValue(""))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error on create path: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: setting a new non-empty value is allowed", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.StringValue("old"), types.StringValue("new"))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error when changing to a new value: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: clearing a non-empty value to null is rejected", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.StringValue("old"), types.StringNull())
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error when clearing a previously-set value")
		}
	})

	t.Run("existing resource: clearing a non-empty value to empty string is rejected", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.StringValue("old"), types.StringValue(""))
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error when clearing to empty string")
		}
	})

	t.Run("existing resource: both state and plan empty is a no-op", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.StringValue(""), types.StringValue(""))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: unknown plan value (e.g. depends on another resource) is not a clear attempt", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.StringValue("old"), types.StringUnknown())
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error for unknown plan value: %v", resp.Diagnostics)
		}
	})
}

func Test_CM_ClearRejectInt64Modifier(t *testing.T) {
	mod := clearRejectInt64Modifier{FieldName: "usage_mask"}

	run := func(stateRaw tfsdk.State, stateVal, planVal types.Int64) planmodifier.Int64Response {
		req := planmodifier.Int64Request{State: stateRaw, StateValue: stateVal, PlanValue: planVal}
		resp := planmodifier.Int64Response{PlanValue: planVal}
		mod.PlanModifyInt64(context.Background(), req, &resp)
		return resp
	}

	t.Run("brand-new resource: passes through, no error", func(t *testing.T) {
		resp := run(tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil)}, types.Int64Null(), types.Int64Value(12))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error on create path: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: changing to a new value is allowed", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.Int64Value(12), types.Int64Value(76))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error when changing to a new value: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: explicit 0 is a real value, not a clear attempt", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.Int64Value(12), types.Int64Value(0))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error when setting to 0: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: clearing a non-null value by omission is rejected", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.Int64Value(12), types.Int64Null())
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error when clearing a previously-set value")
		}
	})

	t.Run("existing resource: both state and plan null is a no-op", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.Int64Null(), types.Int64Null())
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: unknown plan value (e.g. depends on another resource) is not a clear attempt", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), types.Int64Value(12), types.Int64Unknown())
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error for unknown plan value: %v", resp.Diagnostics)
		}
	})
}

func Test_CM_ClearRejectMapModifier(t *testing.T) {
	mod := clearRejectMapModifier{FieldName: "labels"}

	nonEmptyMap := types.MapValueMust(types.StringType, map[string]attr.Value{"env": types.StringValue("prod")})
	emptyMap, _ := types.MapValue(types.StringType, map[string]attr.Value{})

	run := func(stateRaw tfsdk.State, stateVal, planVal types.Map) planmodifier.MapResponse {
		req := planmodifier.MapRequest{State: stateRaw, StateValue: stateVal, PlanValue: planVal}
		resp := planmodifier.MapResponse{PlanValue: planVal}
		mod.PlanModifyMap(context.Background(), req, &resp)
		return resp
	}

	t.Run("brand-new resource: passes through, no error", func(t *testing.T) {
		resp := run(tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil)}, types.MapNull(types.StringType), nonEmptyMap)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error on create path: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: changing to a new non-empty map is allowed", func(t *testing.T) {
		newMap := types.MapValueMust(types.StringType, map[string]attr.Value{"env": types.StringValue("staging")})
		resp := run(nonNullAliasRawState(), nonEmptyMap, newMap)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error when changing to a new map: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: clearing to null is rejected", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), nonEmptyMap, types.MapNull(types.StringType))
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error when clearing to null")
		}
	})

	t.Run("existing resource: clearing to an empty map is rejected", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), nonEmptyMap, emptyMap)
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error when clearing to an empty map")
		}
	})

	t.Run("existing resource: both state and plan empty is a no-op", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), emptyMap, emptyMap)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: unknown plan value (e.g. depends on another resource) is not a clear attempt", func(t *testing.T) {
		resp := run(nonNullAliasRawState(), nonEmptyMap, types.MapUnknown(types.StringType))
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error for unknown plan value: %v", resp.Diagnostics)
		}
	})
}
