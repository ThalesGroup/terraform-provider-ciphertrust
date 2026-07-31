package modifiers_test

import (
	"context"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// objectOf builds a types.Object from string-typed attributes for test brevity.
// Pass a nil value for a given key to make that attribute null.
func objectOf(t *testing.T, values map[string]*string) types.Object {
	t.Helper()
	attrTypes := map[string]attr.Type{}
	attrVals := map[string]attr.Value{}
	for k, v := range values {
		attrTypes[k] = types.StringType
		if v == nil {
			attrVals[k] = types.StringNull()
		} else {
			attrVals[k] = types.StringValue(*v)
		}
	}
	obj, diags := types.ObjectValue(attrTypes, attrVals)
	if diags.HasError() {
		t.Fatalf("failed to build test object: %v", diags)
	}
	return obj
}

func strPtr(s string) *string { return &s }

func Test_CM_MergePatchObject(t *testing.T) {
	mod := modifiers.MergePatchObject()

	run := func(stateVal, planVal types.Object) (types.Object, planmodifier.ObjectResponse) {
		req := planmodifier.ObjectRequest{
			StateValue: stateVal,
			PlanValue:  planVal,
		}
		resp := &planmodifier.ObjectResponse{PlanValue: planVal}
		mod.PlanModifyObject(context.Background(), req, resp)
		return resp.PlanValue, *resp
	}

	t.Run("brand-new resource: any plan value passes through unchanged", func(t *testing.T) {
		plan := objectOf(t, map[string]*string{"owner_id": strPtr("admin")})
		got, resp := run(types.ObjectNull(plan.AttributeTypes(context.Background())), plan)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error on create path: %v", resp.Diagnostics)
		}
		if !got.Equal(plan) {
			t.Errorf("expected plan value to pass through unchanged, got %v", got)
		}
	})

	t.Run("existing resource: adding a new field alongside an unchanged field is allowed", func(t *testing.T) {
		state := objectOf(t, map[string]*string{"owner_id": strPtr("admin"), "other_field": nil})
		plan := objectOf(t, map[string]*string{"owner_id": strPtr("admin"), "other_field": strPtr("test123")})
		_, resp := run(state, plan)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected adding a field to be allowed, got error: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: changing an existing field's value is allowed", func(t *testing.T) {
		state := objectOf(t, map[string]*string{"owner_id": strPtr("admin")})
		plan := objectOf(t, map[string]*string{"owner_id": strPtr("admin2")})
		_, resp := run(state, plan)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected changing a field value to be allowed, got error: %v", resp.Diagnostics)
		}
	})

	t.Run("existing resource: clearing a previously-set field by omission is rejected", func(t *testing.T) {
		state := objectOf(t, map[string]*string{"owner_id": strPtr("admin"), "other_field": strPtr("x")})
		plan := objectOf(t, map[string]*string{"owner_id": strPtr("admin"), "other_field": nil})
		_, resp := run(state, plan)
		if !resp.Diagnostics.HasError() {
			t.Error("expected clearing a set field to null to be rejected")
		}
	})

	t.Run("existing resource: clearing the whole object is rejected", func(t *testing.T) {
		state := objectOf(t, map[string]*string{"owner_id": strPtr("admin")})
		plan := types.ObjectNull(state.AttributeTypes(context.Background()))
		_, resp := run(state, plan)
		if !resp.Diagnostics.HasError() {
			t.Error("expected clearing the whole object to be rejected")
		}
	})

	t.Run("existing resource: unrelated field left unchanged is not treated as a clear", func(t *testing.T) {
		state := objectOf(t, map[string]*string{"owner_id": strPtr("admin"), "other_field": strPtr("x")})
		plan := objectOf(t, map[string]*string{"owner_id": strPtr("admin2"), "other_field": strPtr("x")})
		_, resp := run(state, plan)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected no error when unrelated field is unchanged, got: %v", resp.Diagnostics)
		}
	})
}
