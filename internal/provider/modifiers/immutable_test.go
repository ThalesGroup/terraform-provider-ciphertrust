package modifiers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---- ImmutableString tests ------------------------------------------------------

// Test_CM_ImmutableString_NullPlanValue verifies that ImmutableString does not fire
// when the plan value is null (e.g. during a destroy-triggered refresh or framework
// null-plan phase), even when the state value is non-null.
func Test_CM_ImmutableString_NullPlanValue(t *testing.T) {
	mod := modifiers.ImmutableString()

	req := planmodifier.StringRequest{
		State:      nonNullRawState(),
		StateValue: types.StringValue("cluster"),
		PlanValue:  types.StringNull(),
	}
	resp := &planmodifier.StringResponse{PlanValue: types.StringNull()}
	mod.PlanModifyString(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error when PlanValue is null, got: %v", resp.Diagnostics)
	}
}

// Test_CM_ImmutableString_UnknownPlanValue verifies that ImmutableString does not fire
// when the plan value is unknown (e.g. computed-after-apply or UseStateForUnknown resolution).
func Test_CM_ImmutableString_UnknownPlanValue(t *testing.T) {
	mod := modifiers.ImmutableString()

	req := planmodifier.StringRequest{
		State:      nonNullRawState(),
		StateValue: types.StringValue("cluster"),
		PlanValue:  types.StringUnknown(),
	}
	resp := &planmodifier.StringResponse{PlanValue: types.StringUnknown()}
	mod.PlanModifyString(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error when PlanValue is unknown, got: %v", resp.Diagnostics)
	}
}

// Test_CM_ImmutableString_GenuineChange verifies that ImmutableString fires an error
// when both StateValue and PlanValue are non-null and differ — a genuine attempted change.
func Test_CM_ImmutableString_GenuineChange(t *testing.T) {
	mod := modifiers.ImmutableString()

	req := planmodifier.StringRequest{
		State:      nonNullRawState(),
		StateValue: types.StringValue("cluster"),
		PlanValue:  types.StringValue("hsm"),
	}
	resp := &planmodifier.StringResponse{PlanValue: types.StringValue("hsm")}
	mod.PlanModifyString(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for genuine immutable change, got none")
	}
	found := false
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Summary(), "Attribute is immutable") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error summary to contain 'Attribute is immutable', diagnostics: %v", resp.Diagnostics)
	}
}

// ---- ImmutableMap tests ---------------------------------------------------------

// Test_CM_ImmutableMap_NullPlanValue verifies that ImmutableMap does not fire when
// the plan value is null.
func Test_CM_ImmutableMap_NullPlanValue(t *testing.T) {
	mod := modifiers.ImmutableMap()

	stateMap := types.MapValueMust(types.StringType, map[string]attr.Value{
		"partition_name": types.StringValue("kylo-partition"),
	})

	req := planmodifier.MapRequest{
		State:      nonNullRawState(),
		StateValue: stateMap,
		PlanValue:  types.MapNull(types.StringType),
	}
	resp := &planmodifier.MapResponse{PlanValue: types.MapNull(types.StringType)}
	mod.PlanModifyMap(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error when PlanValue is null, got: %v", resp.Diagnostics)
	}
}

// Test_CM_ImmutableMap_UnknownPlanValue verifies that ImmutableMap does not fire when
// the plan value is unknown.
func Test_CM_ImmutableMap_UnknownPlanValue(t *testing.T) {
	mod := modifiers.ImmutableMap()

	stateMap := types.MapValueMust(types.StringType, map[string]attr.Value{
		"partition_name": types.StringValue("kylo-partition"),
	})

	req := planmodifier.MapRequest{
		State:      nonNullRawState(),
		StateValue: stateMap,
		PlanValue:  types.MapUnknown(types.StringType),
	}
	resp := &planmodifier.MapResponse{PlanValue: types.MapUnknown(types.StringType)}
	mod.PlanModifyMap(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error when PlanValue is unknown, got: %v", resp.Diagnostics)
	}
}

// Test_CM_ImmutableMap_GenuineChange verifies that ImmutableMap fires an error when
// both StateValue and PlanValue are non-null with differing map contents.
func Test_CM_ImmutableMap_GenuineChange(t *testing.T) {
	mod := modifiers.ImmutableMap()

	stateMap := types.MapValueMust(types.StringType, map[string]attr.Value{
		"partition_name": types.StringValue("partition-one"),
	})
	planMap := types.MapValueMust(types.StringType, map[string]attr.Value{
		"partition_name": types.StringValue("partition-two"),
	})

	req := planmodifier.MapRequest{
		State:      nonNullRawState(),
		StateValue: stateMap,
		PlanValue:  planMap,
	}
	resp := &planmodifier.MapResponse{PlanValue: planMap}
	mod.PlanModifyMap(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for genuine immutable map change, got none")
	}
	found := false
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Detail(), "cannot be changed after creation") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error detail to contain 'cannot be changed after creation', diagnostics: %v", resp.Diagnostics)
	}
}
