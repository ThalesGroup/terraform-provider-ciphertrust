package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// minimalMLDSASchema returns a schema with only the two attributes exercised
// by mlDSAParameterSetValidator, avoiding the need for a full provider setup.
func minimalMLDSASchema() rschema.Schema {
	return rschema.Schema{
		Attributes: map[string]rschema.Attribute{
			"algorithm":            rschema.StringAttribute{Optional: true},
			"ml_dsa_parameter_set": rschema.StringAttribute{Optional: true},
		},
	}
}

func buildMLDSAConfig(algorithm, parameterSet string) tfsdk.Config {
	objType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"algorithm":            tftypes.String,
			"ml_dsa_parameter_set": tftypes.String,
		},
	}
	algVal := tftypes.NewValue(tftypes.String, nil)
	if algorithm != "" {
		algVal = tftypes.NewValue(tftypes.String, algorithm)
	}
	paramVal := tftypes.NewValue(tftypes.String, nil)
	if parameterSet != "" {
		paramVal = tftypes.NewValue(tftypes.String, parameterSet)
	}
	return tfsdk.Config{
		Schema: minimalMLDSASchema(),
		Raw: tftypes.NewValue(objType, map[string]tftypes.Value{
			"algorithm":            algVal,
			"ml_dsa_parameter_set": paramVal,
		}),
	}
}

func TestMLDSAParameterSetValidator_RejectsParameterSetOnNonMLDSA(t *testing.T) {
	ctx := context.Background()
	v := mlDSAParameterSetValidator{}
	var resp resource.ValidateConfigResponse

	v.ValidateResource(ctx, resource.ValidateConfigRequest{
		Config: buildMLDSAConfig("aes", "ML-DSA-65"),
	}, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected validation error for ml_dsa_parameter_set with non-ml-dsa algorithm, got none")
	}
}

func TestMLDSAParameterSetValidator_AllowsParameterSetOnMLDSA(t *testing.T) {
	ctx := context.Background()
	v := mlDSAParameterSetValidator{}
	var resp resource.ValidateConfigResponse

	v.ValidateResource(ctx, resource.ValidateConfigRequest{
		Config: buildMLDSAConfig("ml-dsa", "ML-DSA-65"),
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected validation error for ml_dsa_parameter_set with ml-dsa algorithm: %v", resp.Diagnostics)
	}
}

func TestMLDSAParameterSetValidator_AllowsAbsentParameterSet(t *testing.T) {
	ctx := context.Background()
	v := mlDSAParameterSetValidator{}
	var resp resource.ValidateConfigResponse

	v.ValidateResource(ctx, resource.ValidateConfigRequest{
		Config: buildMLDSAConfig("aes", ""),
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected validation error when ml_dsa_parameter_set is absent: %v", resp.Diagnostics)
	}
}
