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

	// updatePlanRaw simulates a non-destroy plan. The MergePatchObject modifier now
	// guards on req.Plan.Raw.IsNull() to skip the check during destroy operations
	// (TFIN-552); tests that simulate updates must set Plan.Raw to a non-null value.
	updatePlanRaw := tfsdk.Plan{Raw: tftypes.NewValue(
		tftypes.Object{AttributeTypes: map[string]tftypes.Type{"x": tftypes.String}},
		map[string]tftypes.Value{"x": tftypes.NewValue(tftypes.String, "v")},
	)}

	run := func(stateVal, planVal types.Object) (types.Object, planmodifier.ObjectResponse) {
		req := planmodifier.ObjectRequest{
			Plan:       updatePlanRaw,
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

	t.Run("existing resource: clearing multiple fields at once reports them in a deterministic (sorted) order", func(t *testing.T) {
		state := objectOf(t, map[string]*string{"zebra": strPtr("z"), "alpha": strPtr("a"), "mango": strPtr("m")})
		plan := objectOf(t, map[string]*string{"zebra": nil, "alpha": nil, "mango": nil})
		want := "" // computed on first iteration, then compared on every subsequent one
		for i := 0; i < 20; i++ {
			_, resp := run(state, plan)
			if !resp.Diagnostics.HasError() {
				t.Fatal("expected clearing multiple fields to be rejected")
			}
			got := resp.Diagnostics[0].Detail()
			if want == "" {
				want = got
				continue
			}
			if got != want {
				t.Fatalf("error message ordering is non-deterministic across runs:\nfirst: %s\nlater: %s", want, got)
			}
		}
	})
}
