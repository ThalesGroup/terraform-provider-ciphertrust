// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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

// nullRawState returns a tfsdk.State whose Raw is the null tftypes value —
// this is what the framework passes for a brand-new resource (no prior state).
func nullRawState() tfsdk.State {
	return tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil)}
}

// nonNullRawState returns a tfsdk.State whose Raw is non-null —
// simulating an existing resource that was previously created.
func nonNullRawState() tfsdk.State {
	return tfsdk.State{
		Raw: tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{},
		}, map[string]tftypes.Value{}),
	}
}

// ---- UseStateWhenClearingString -------------------------------------------------

// Test_UseStateWhenClearingString verifies that the modifier leaves the plan value
// unchanged except when it would try to clear (empty string / null) a non-empty
// state value on an existing resource.
func Test_CM_UseStateWhenClearingString(t *testing.T) {
	mod := modifiers.UseStateWhenClearingString()

	run := func(stateRaw tfsdk.State, stateVal, planVal types.String) types.String {
		req := planmodifier.StringRequest{
			State:      stateRaw,
			StateValue: stateVal,
			PlanValue:  planVal,
		}
		resp := &planmodifier.StringResponse{PlanValue: planVal}
		mod.PlanModifyString(context.Background(), req, resp)
		return resp.PlanValue
	}

	t.Run("brand-new resource: empty plan value passes through unchanged", func(t *testing.T) {
		got := run(nullRawState(), types.StringNull(), types.StringValue(""))
		if got.ValueString() != "" {
			t.Errorf("expected empty string, got %q", got.ValueString())
		}
	})

	t.Run("brand-new resource: non-empty plan value passes through unchanged", func(t *testing.T) {
		got := run(nullRawState(), types.StringNull(), types.StringValue("hello"))
		if got.ValueString() != "hello" {
			t.Errorf("expected %q, got %q", "hello", got.ValueString())
		}
	})

	t.Run("existing resource: non-empty plan value passes through unchanged", func(t *testing.T) {
		got := run(nonNullRawState(), types.StringValue("old"), types.StringValue("new"))
		if got.ValueString() != "new" {
			t.Errorf("expected %q, got %q", "new", got.ValueString())
		}
	})

	t.Run("existing resource: empty-string plan attempting to clear non-empty state → state preserved", func(t *testing.T) {
		got := run(nonNullRawState(), types.StringValue("some text"), types.StringValue(""))
		if got.ValueString() != "some text" {
			t.Errorf("expected state value %q to be preserved, got %q", "some text", got.ValueString())
		}
	})

	t.Run("existing resource: null plan attempting to clear non-empty state → state preserved", func(t *testing.T) {
		got := run(nonNullRawState(), types.StringValue("some text"), types.StringNull())
		if got.ValueString() != "some text" {
			t.Errorf("expected state value %q to be preserved, got %q", "some text", got.ValueString())
		}
	})

	t.Run("existing resource: both state and plan empty → no substitution", func(t *testing.T) {
		got := run(nonNullRawState(), types.StringValue(""), types.StringValue(""))
		if got.ValueString() != "" {
			t.Errorf("expected empty string, got %q", got.ValueString())
		}
	})

	t.Run("existing resource: state empty, plan null → no substitution (nothing to preserve)", func(t *testing.T) {
		got := run(nonNullRawState(), types.StringValue(""), types.StringNull())
		if !got.IsNull() {
			t.Errorf("expected null plan value to pass through, got %q", got.ValueString())
		}
	})

	t.Run("existing resource: clearing a non-empty state value surfaces a warning diagnostic", func(t *testing.T) {
		req := planmodifier.StringRequest{
			State:      nonNullRawState(),
			StateValue: types.StringValue("some text"),
			PlanValue:  types.StringNull(),
		}
		resp := &planmodifier.StringResponse{PlanValue: types.StringNull()}
		mod.PlanModifyString(context.Background(), req, resp)
		if len(resp.Diagnostics.Warnings()) == 0 {
			t.Error("expected a warning diagnostic when a clear is silently ignored")
		}
	})
}

// ---- UseStateWhenClearingMap ---------------------------------------------------

// Test_UseStateWhenClearingMap verifies that the modifier leaves the plan map
// unchanged except when it would try to clear (null or empty map) a non-empty
// state map on an existing resource.
func Test_CM_UseStateWhenClearingMap(t *testing.T) {
	mod := modifiers.UseStateWhenClearingMap()

	nonEmptyMap := types.MapValueMust(types.StringType, map[string]attr.Value{
		"env": types.StringValue("prod"),
	})
	emptyMap, _ := types.MapValue(types.StringType, map[string]attr.Value{})

	run := func(stateRaw tfsdk.State, stateVal, planVal types.Map) types.Map {
		req := planmodifier.MapRequest{
			State:      stateRaw,
			StateValue: stateVal,
			PlanValue:  planVal,
		}
		resp := &planmodifier.MapResponse{PlanValue: planVal}
		mod.PlanModifyMap(context.Background(), req, resp)
		return resp.PlanValue
	}

	t.Run("brand-new resource: null plan passes through unchanged", func(t *testing.T) {
		got := run(nullRawState(), types.MapNull(types.StringType), types.MapNull(types.StringType))
		if !got.IsNull() {
			t.Errorf("expected null map to pass through for new resource, got %v", got)
		}
	})

	t.Run("brand-new resource: non-empty plan passes through unchanged", func(t *testing.T) {
		got := run(nullRawState(), types.MapNull(types.StringType), nonEmptyMap)
		if len(got.Elements()) != 1 {
			t.Errorf("expected 1 element, got %d", len(got.Elements()))
		}
	})

	t.Run("existing resource: non-empty plan passes through unchanged", func(t *testing.T) {
		newMap := types.MapValueMust(types.StringType, map[string]attr.Value{
			"env": types.StringValue("staging"),
		})
		got := run(nonNullRawState(), nonEmptyMap, newMap)
		elems := got.Elements()
		if v, ok := elems["env"]; !ok || v.(types.String).ValueString() != "staging" {
			t.Errorf("expected plan value to pass through unchanged, got %v", got)
		}
	})

	t.Run("existing resource: null plan attempting to clear non-empty state → state preserved", func(t *testing.T) {
		got := run(nonNullRawState(), nonEmptyMap, types.MapNull(types.StringType))
		if len(got.Elements()) != 1 {
			t.Errorf("expected state map to be preserved (1 element), got %d elements", len(got.Elements()))
		}
		if _, ok := got.Elements()["env"]; !ok {
			t.Errorf("expected 'env' key preserved from state, got %v", got.Elements())
		}
	})

	t.Run("existing resource: empty map plan attempting to clear non-empty state → state preserved", func(t *testing.T) {
		got := run(nonNullRawState(), nonEmptyMap, emptyMap)
		if len(got.Elements()) != 1 {
			t.Errorf("expected state map to be preserved (1 element), got %d elements", len(got.Elements()))
		}
	})

	t.Run("existing resource: both state and plan empty → no substitution", func(t *testing.T) {
		got := run(nonNullRawState(), emptyMap, emptyMap)
		if len(got.Elements()) != 0 {
			t.Errorf("expected empty plan to pass through, got %v", got.Elements())
		}
	})

	t.Run("existing resource: state null, plan null → no substitution (nothing to preserve)", func(t *testing.T) {
		got := run(nonNullRawState(), types.MapNull(types.StringType), types.MapNull(types.StringType))
		if !got.IsNull() {
			t.Errorf("expected null plan to pass through when state is also null, got %v", got)
		}
	})

	t.Run("existing resource: clearing a non-empty state map surfaces a warning diagnostic", func(t *testing.T) {
		req := planmodifier.MapRequest{
			State:      nonNullRawState(),
			StateValue: nonEmptyMap,
			PlanValue:  types.MapNull(types.StringType),
		}
		resp := &planmodifier.MapResponse{PlanValue: types.MapNull(types.StringType)}
		mod.PlanModifyMap(context.Background(), req, resp)
		if len(resp.Diagnostics.Warnings()) == 0 {
			t.Error("expected a warning diagnostic when a clear is silently ignored")
		}
	})
}
