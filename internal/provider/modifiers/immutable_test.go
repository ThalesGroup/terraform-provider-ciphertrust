package modifiers_test

import (
	"context"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Test_CM_ImmutableStringNullPlan documents that ImmutableString() already
// correctly rejects a null plan value on an existing resource (no regression
// introduced by the TFIN-425 fix, which only touched Bool and Int64).
func Test_CM_ImmutableStringNullPlan(t *testing.T) {
	mod := modifiers.ImmutableString()
	req := planmodifier.StringRequest{
		State:      nonNullRawState(),
		StateValue: types.StringValue("original"),
		PlanValue:  types.StringNull(),
	}
	resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}
	mod.PlanModifyString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when null plan attempts to clear an immutable string attribute")
	}
}

// Test_CM_ImmutableBoolNullPlan verifies that ImmutableBool() rejects a null plan
// value on an existing resource. A null plan value means the user removed the
// attribute from config after it was set — that is an immutability violation, not
// an innocuous omission.
func Test_CM_ImmutableBoolNullPlan(t *testing.T) {
	mod := modifiers.ImmutableBool()
	req := planmodifier.BoolRequest{
		State:      nonNullRawState(),
		StateValue: types.BoolValue(true),
		PlanValue:  types.BoolNull(),
	}
	resp := &planmodifier.BoolResponse{PlanValue: req.PlanValue}
	mod.PlanModifyBool(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when null plan attempts to clear an immutable bool attribute")
	}
}

// Test_CM_ImmutableBoolUnknownPlan verifies that ImmutableBool() allows an
// unknown plan value (from another resource's output).
func Test_CM_ImmutableBoolUnknownPlan(t *testing.T) {
	mod := modifiers.ImmutableBool()
	req := planmodifier.BoolRequest{
		State:      nonNullRawState(),
		StateValue: types.BoolValue(true),
		PlanValue:  types.BoolUnknown(),
	}
	resp := &planmodifier.BoolResponse{PlanValue: req.PlanValue}
	mod.PlanModifyBool(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error for unknown plan value: %s", resp.Diagnostics)
	}
}

// Test_CM_ImmutableBoolChange verifies that ImmutableBool() rejects a change
// from true to false (a genuine value-change, not a null transition).
func Test_CM_ImmutableBoolChange(t *testing.T) {
	mod := modifiers.ImmutableBool()
	req := planmodifier.BoolRequest{
		State:      nonNullRawState(),
		StateValue: types.BoolValue(true),
		PlanValue:  types.BoolValue(false),
	}
	resp := &planmodifier.BoolResponse{PlanValue: req.PlanValue}
	mod.PlanModifyBool(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when bool attribute is changed on existing resource")
	}
}

// Test_CM_ImmutableInt64NullPlan verifies that ImmutableInt64() rejects a null plan
// value on an existing resource. A null plan value means the user removed the
// attribute from config after it was set — that is an immutability violation.
func Test_CM_ImmutableInt64NullPlan(t *testing.T) {
	mod := modifiers.ImmutableInt64()
	req := planmodifier.Int64Request{
		State:      nonNullRawState(),
		StateValue: types.Int64Value(42),
		PlanValue:  types.Int64Null(),
	}
	resp := &planmodifier.Int64Response{PlanValue: req.PlanValue}
	mod.PlanModifyInt64(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when null plan attempts to clear an immutable int64 attribute")
	}
}

// Test_CM_ImmutableInt64UnknownPlan verifies that ImmutableInt64() allows an
// unknown plan value (from another resource's output).
func Test_CM_ImmutableInt64UnknownPlan(t *testing.T) {
	mod := modifiers.ImmutableInt64()
	req := planmodifier.Int64Request{
		State:      nonNullRawState(),
		StateValue: types.Int64Value(42),
		PlanValue:  types.Int64Unknown(),
	}
	resp := &planmodifier.Int64Response{PlanValue: req.PlanValue}
	mod.PlanModifyInt64(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error for unknown plan value: %s", resp.Diagnostics)
	}
}

// Test_CM_ImmutableListNullPlan documents that ImmutableList() already
// correctly rejects a null plan value on an existing resource.
func Test_CM_ImmutableListNullPlan(t *testing.T) {
	mod := modifiers.ImmutableList()
	stateList := types.ListValueMust(types.StringType, []attr.Value{types.StringValue("a")})
	req := planmodifier.ListRequest{
		State:      nonNullRawState(),
		StateValue: stateList,
		PlanValue:  types.ListNull(types.StringType),
	}
	resp := &planmodifier.ListResponse{PlanValue: req.PlanValue}
	mod.PlanModifyList(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when null plan attempts to clear an immutable list attribute")
	}
}

// Test_CM_ImmutableNewResource verifies that all immutable modifiers allow any
// value when the resource is brand-new (State.Raw.IsNull()).
func Test_CM_ImmutableNewResource(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		mod := modifiers.ImmutableString()
		req := planmodifier.StringRequest{
			State:      nullRawState(),
			StateValue: types.StringNull(),
			PlanValue:  types.StringValue("any"),
		}
		resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}
		mod.PlanModifyString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("brand-new resource must not trigger immutability error: %s", resp.Diagnostics)
		}
	})
	t.Run("bool", func(t *testing.T) {
		mod := modifiers.ImmutableBool()
		req := planmodifier.BoolRequest{
			State:      nullRawState(),
			StateValue: types.BoolNull(),
			PlanValue:  types.BoolValue(true),
		}
		resp := &planmodifier.BoolResponse{PlanValue: req.PlanValue}
		mod.PlanModifyBool(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("brand-new resource must not trigger immutability error: %s", resp.Diagnostics)
		}
	})
	t.Run("int64", func(t *testing.T) {
		mod := modifiers.ImmutableInt64()
		req := planmodifier.Int64Request{
			State:      nullRawState(),
			StateValue: types.Int64Null(),
			PlanValue:  types.Int64Value(7),
		}
		resp := &planmodifier.Int64Response{PlanValue: req.PlanValue}
		mod.PlanModifyInt64(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("brand-new resource must not trigger immutability error: %s", resp.Diagnostics)
		}
	})
	t.Run("list", func(t *testing.T) {
		mod := modifiers.ImmutableList()
		req := planmodifier.ListRequest{
			State:      nullRawState(),
			StateValue: types.ListNull(types.StringType),
			PlanValue:  types.ListValueMust(types.StringType, []attr.Value{types.StringValue("x")}),
		}
		resp := &planmodifier.ListResponse{PlanValue: req.PlanValue}
		mod.PlanModifyList(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("brand-new resource must not trigger immutability error: %s", resp.Diagnostics)
		}
	})
}
