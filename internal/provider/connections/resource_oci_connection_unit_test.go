package connections

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Test_CM_GetOciParamsFromResponse_DescriptionDrift verifies that getOciParamsFromResponse
// correctly syncs the description field from the CM API response, ensuring that:
//   - A non-empty CM description overwrites any stale value in state (drift detected).
//   - An empty/absent CM description sets state to null, clearing stale injected values
//     (previously the bug: stale state was preserved when CM had no description).
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
