package cckm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// azureCertOfflineRaw turns a model into the raw tftypes value of the schema.
func azureCertOfflineRaw(ctx context.Context, t *testing.T, s schema.Schema, model interface{}) tftypes.Value {
	t.Helper()
	state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	diags := state.Set(ctx, model)
	if diags.HasError() {
		t.Fatalf("building a value from the model failed: %v", diags)
	}
	return state.Raw
}

// azureCertOfflineDiffs lists every path where two values differ.
func azureCertOfflineDiffs(a tftypes.Value, b tftypes.Value) []string {
	diffs, err := a.Diff(b)
	if err != nil {
		return []string{"diff error: " + err.Error()}
	}
	lines := make([]string, 0, len(diffs))
	for _, diff := range diffs {
		left, right := "<nil>", "<nil>"
		if diff.Value1 != nil {
			left = diff.Value1.String()
		}
		if diff.Value2 != nil {
			right = diff.Value2.String()
		}
		lines = append(lines, diff.Path.String()+": "+left+" vs "+right)
	}
	return lines
}

// azureCertOfflinePropose mimics the proposed new state Terraform core builds: the prior value for an
// attribute that is computed and null in the config, and the config value otherwise. It recurses into
// single nested attributes only, so a list of objects takes the config value as it is.
func azureCertOfflinePropose(attrs map[string]schema.Attribute, cfg tftypes.Value, prior tftypes.Value) (tftypes.Value, error) {
	cfgMap := map[string]tftypes.Value{}
	if err := cfg.As(&cfgMap); err != nil {
		return cfg, err
	}
	priorMap := map[string]tftypes.Value{}
	if err := prior.As(&priorMap); err != nil {
		return cfg, err
	}
	out := make(map[string]tftypes.Value, len(cfgMap))
	for name, cfgValue := range cfgMap {
		attribute := attrs[name]
		priorValue := priorMap[name]
		if cfgValue.IsNull() && attribute.IsComputed() {
			out[name] = priorValue
			continue
		}
		nested, isNested := attribute.(schema.SingleNestedAttribute)
		if isNested && !priorValue.IsNull() {
			value, err := azureCertOfflinePropose(nested.Attributes, cfgValue, priorValue)
			if err != nil {
				return cfg, err
			}
			out[name] = value
			continue
		}
		out[name] = cfgValue
	}
	return tftypes.NewValue(cfg.Type(), out), nil
}

func azureCertOfflineCheckDiags(t *testing.T, label string, diags []*tfprotov6.Diagnostic) {
	t.Helper()
	for _, diag := range diags {
		message := label + " diagnostic: " + diag.Summary + " - " + diag.Detail
		if diag.Severity == tfprotov6.DiagnosticSeverityError {
			t.Errorf("%s", message)
			continue
		}
		t.Logf("%s", message)
	}
}

func azureCertOfflineEncode(t *testing.T, kind string, typ tftypes.Type, value tftypes.Value) *tfprotov6.DynamicValue {
	t.Helper()
	encoded, err := tfprotov6.NewDynamicValue(typ, value)
	if err != nil {
		t.Fatalf("[%s] encoding a value failed: %v", kind, err)
	}
	return &encoded
}
