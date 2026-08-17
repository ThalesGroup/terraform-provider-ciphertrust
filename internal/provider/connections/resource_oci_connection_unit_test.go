package connections

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Test_CM_GetOciParamsFromResponse_DescriptionDrift verifies that
// getOciParamsFromResponse syncs description from the CM API response: a
// non-empty value overwrites stale state, and an empty/absent one nulls it.
func Test_CM_GetOciParamsFromResponse_DescriptionDrift(t *testing.T) {
	r := &resourceCCKMOCIConnection{}

	t.Run("non-empty CM description overwrites stale state value", func(t *testing.T) {
		var data OCIConnectionTFSDK
		// Simulate stale state: description was "STALE" before refresh
		data.Description = types.StringValue("STALE")

		response := `{"id":"abc","name":"test","description":"LIVE_DRIFT_DESCRIPTION","uri":"","account":"","updatedAt":"","createdAt":"","category":"","resource_url":"","service":"","last_connection_ok":false,"last_connection_error":"","last_connection_at":"","fingerprint":"","region":"","tenancy_ocid":"","user_ocid":""}`
		var diags diag.Diagnostics
		r.getOciParamsFromResponse(context.Background(), response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if data.Description.IsNull() {
			t.Error("expected description to be set but got null")
		}
		if got := data.Description.ValueString(); got != "LIVE_DRIFT_DESCRIPTION" {
			t.Errorf("expected description = %q, got %q", "LIVE_DRIFT_DESCRIPTION", got)
		}
	})

	t.Run("absent CM description clears stale state value to null (regression for drift-invisible bug)", func(t *testing.T) {
		var data OCIConnectionTFSDK
		// Simulate stale/injected state: description was "FAKE_INJECTED" before refresh
		data.Description = types.StringValue("FAKE_INJECTED")

		// CM response has no description field
		response := `{"id":"abc","name":"test","uri":"","account":"","updatedAt":"","createdAt":"","category":"","resource_url":"","service":"","last_connection_ok":false,"last_connection_error":"","last_connection_at":"","fingerprint":"","region":"","tenancy_ocid":"","user_ocid":""}`
		var diags diag.Diagnostics
		r.getOciParamsFromResponse(context.Background(), response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if !data.Description.IsNull() {
			t.Errorf("expected description to be null when CM returns no description, got %q", data.Description.ValueString())
		}
	})

	t.Run("empty-string CM description clears stale state value to null", func(t *testing.T) {
		var data OCIConnectionTFSDK
		data.Description = types.StringValue("FAKE_INJECTED")

		// CM response has description = ""
		response := `{"id":"abc","name":"test","description":"","uri":"","account":"","updatedAt":"","createdAt":"","category":"","resource_url":"","service":"","last_connection_ok":false,"last_connection_error":"","last_connection_at":"","fingerprint":"","region":"","tenancy_ocid":"","user_ocid":""}`
		var diags diag.Diagnostics
		r.getOciParamsFromResponse(context.Background(), response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if !data.Description.IsNull() {
			t.Errorf("expected description to be null when CM returns empty description, got %q", data.Description.ValueString())
		}
	})
}

// Test_CM_GetOciParamsFromResponse_ExplicitEmptyValuesSurvive is a regression test for a bug
// where `description = ""` or `meta = {}` in config would crash Create/Update with
// "Provider produced inconsistent result after apply" (.description/.meta: was <empty>, but
// now null), because getOciParamsFromResponse always collapsed an absent/null CM field to
// null — even when the planned value was a deliberately-empty, known (non-null) value that
// Terraform then required back verbatim.
func Test_CM_GetOciParamsFromResponse_ExplicitEmptyValuesSurvive(t *testing.T) {
	r := &resourceCCKMOCIConnection{}

	baseResponse := `{"id":"abc","name":"test","uri":"","account":"","updatedAt":"","createdAt":"","category":"","resource_url":"","service":"","last_connection_ok":false,"last_connection_error":"","last_connection_at":"","fingerprint":"","region":"","tenancy_ocid":"","user_ocid":""`

	responses := map[string]string{
		"meta/description absent from CM response": baseResponse + `}`,
		"meta null, description absent":            baseResponse + `,"meta":null}`,
		"meta empty object, description empty":     baseResponse + `,"meta":{},"description":""}`,
	}

	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			var data OCIConnectionTFSDK
			// Simulate a planned/config value of description = "" and meta = {}: known,
			// non-null, empty values — exactly what Create()/Update() pass in before calling
			// getOciParamsFromResponse to hydrate the rest of the fields from CM's response.
			data.Description = types.StringValue("")
			data.Meta = types.MapValueMust(types.StringType, map[string]attr.Value{})

			var diags diag.Diagnostics
			r.getOciParamsFromResponse(context.Background(), response, &diags, &data)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if data.Description.IsNull() {
				t.Error("description was explicitly \"\" in the plan; got null, which would crash Terraform's consistency check")
			} else if data.Description.ValueString() != "" {
				t.Errorf("expected description to remain \"\", got %q", data.Description.ValueString())
			}
			if data.Meta.IsNull() {
				t.Error("meta was explicitly {} in the plan; got null, which would crash Terraform's consistency check")
			} else if len(data.Meta.Elements()) != 0 {
				t.Errorf("expected meta to remain empty, got %v", data.Meta)
			}
		})
	}
}

// Test_CM_GetOciParamsFromResponse_MetaDrift mirrors the existing description drift coverage
// above, for the meta map: a live CM value must still overwrite stale state, and a field that
// truly disappears from a non-empty prior value must still clear to null.
func Test_CM_GetOciParamsFromResponse_MetaDrift(t *testing.T) {
	r := &resourceCCKMOCIConnection{}

	t.Run("non-empty CM meta overwrites stale state value", func(t *testing.T) {
		var data OCIConnectionTFSDK
		data.Meta = types.MapValueMust(types.StringType, map[string]attr.Value{
			"stale": types.StringValue("value"),
		})

		response := `{"id":"abc","name":"test","meta":{"k":"v"},"uri":"","account":"","updatedAt":"","createdAt":"","category":"","resource_url":"","service":"","last_connection_ok":false,"last_connection_error":"","last_connection_at":"","fingerprint":"","region":"","tenancy_ocid":"","user_ocid":""}`
		var diags diag.Diagnostics
		r.getOciParamsFromResponse(context.Background(), response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if data.Meta.IsNull() {
			t.Fatal("expected meta to be set but got null")
		}
		got, ok := data.Meta.Elements()["k"].(types.String)
		if !ok || got.ValueString() != "v" {
			t.Errorf("expected meta[\"k\"] = \"v\", got %v", data.Meta)
		}
	})

	t.Run("meta removed on CM side clears non-empty stale state to null", func(t *testing.T) {
		var data OCIConnectionTFSDK
		// Simulate stale state: meta had real entries before this refresh.
		data.Meta = types.MapValueMust(types.StringType, map[string]attr.Value{
			"stale": types.StringValue("value"),
		})

		response := `{"id":"abc","name":"test","uri":"","account":"","updatedAt":"","createdAt":"","category":"","resource_url":"","service":"","last_connection_ok":false,"last_connection_error":"","last_connection_at":"","fingerprint":"","region":"","tenancy_ocid":"","user_ocid":""}`
		var diags diag.Diagnostics
		r.getOciParamsFromResponse(context.Background(), response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if !data.Meta.IsNull() {
			t.Errorf("expected meta to be null when CM has genuinely dropped a previously non-empty value, got %v", data.Meta)
		}
	})
}
