package cm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Test_CM_RegToken_buildLabelsPatch_ClearPath verifies that buildLabelsPatch
// emits nil (→ JSON null) when the user clears labels (plan null, state non-null).
// This is the key signal CM needs to remove all labels from the resource.
func Test_CM_RegToken_buildLabelsPatch_ClearPath(t *testing.T) {
	// State: labels were previously set
	stateLabels, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{"env": "test"})
	state := CMRegTokenTFSDK{Labels: stateLabels}

	// Plan: labels removed from config (null)
	plan := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}

	result := buildLabelsPatch(plan, state)

	if result == skipLabels {
		t.Fatal("expected nil (clear signal), got skipLabels (omit)")
	}
	if result != nil {
		t.Fatalf("expected nil (JSON null), got %v", result)
	}

	// Verify it marshals as "labels": null in the PATCH body
	patchMap := map[string]any{"labels": result}
	b, err := json.Marshal(patchMap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	got := string(b)
	if got != `{"labels":null}` {
		t.Fatalf("expected {\"labels\":null}, got %s", got)
	}
}

// Test_CM_RegToken_buildLabelsPatch_SetPath verifies that buildLabelsPatch
// returns a populated map when labels are configured in the plan.
func Test_CM_RegToken_buildLabelsPatch_SetPath(t *testing.T) {
	planLabels, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{"k": "v"})
	plan := CMRegTokenTFSDK{Labels: planLabels}
	state := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}

	result := buildLabelsPatch(plan, state)

	if result == skipLabels {
		t.Fatal("expected map, got skipLabels")
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", result)
	}
	if m["k"] != "v" {
		t.Fatalf("expected k=v, got %v", m)
	}
}

// Test_CM_RegToken_buildLabelsPatch_NeverConfigured verifies that buildLabelsPatch
// returns skipLabels (omit key) when neither plan nor state has labels configured.
func Test_CM_RegToken_buildLabelsPatch_NeverConfigured(t *testing.T) {
	plan := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}
	state := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}

	result := buildLabelsPatch(plan, state)

	if result != skipLabels {
		t.Fatalf("expected skipLabels (omit key), got %v", result)
	}
}

// Compile-time check: CMRegTokenTFSDK must have a Labels field of types.Map.
var _ attr.Value = CMRegTokenTFSDK{}.Labels

// Test_CM_RegToken_CAIDImmutableRemoved verifies that the ca_id schema attribute
// does NOT carry ImmutableString() in its PlanModifiers. This acts as a regression
// guard: if ImmutableString() is accidentally re-added, this test fails immediately,
// preventing a silent rollback to the incorrect destroy+recreate behavior.
func Test_CM_RegToken_CAIDImmutableRemoved(t *testing.T) {
	r := &resourceCMRegToken{}
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	caIDAttr, ok := resp.Schema.Attributes["ca_id"]
	if !ok {
		t.Fatal("ca_id attribute not found in schema")
	}

	strAttr, ok := caIDAttr.(schema.StringAttribute)
	if !ok {
		t.Fatalf("ca_id is not a StringAttribute, got %T", caIDAttr)
	}

	for _, mod := range strAttr.PlanModifiers {
		desc := mod.Description(context.Background())
		if strings.Contains(strings.ToLower(desc), "immutable") {
			t.Fatalf("ca_id still has an immutability plan modifier: %q — remove it (TFIN-514)", desc)
		}
	}
}
