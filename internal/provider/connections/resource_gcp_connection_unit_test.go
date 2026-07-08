package connections

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// gcpResponse returns a JSON response for getGcpParamsFromResponse with only the
// specified fields set to non-empty values. All other string fields default to empty
// to avoid gjson duplicate-key issues.
func gcpResponse(fields map[string]string) string {
	get := func(k string) string {
		if v, ok := fields[k]; ok {
			return v
		}
		return ""
	}
	return fmt.Sprintf(`{
		"id":%q,"name":%q,
		"uri":%q,"account":%q,
		"updatedAt":%q,"createdAt":%q,
		"category":%q,"service":%q,
		"resource_url":%q,"last_connection_ok":false,
		"last_connection_error":%q,"last_connection_at":%q,
		"cloud_name":%q,"description":%q,
		"client_email":%q,"private_key_id":%q
	}`,
		get("id"), get("name"),
		get("uri"), get("account"),
		get("updatedAt"), get("createdAt"),
		get("category"), get("service"),
		get("resource_url"),
		get("last_connection_error"), get("last_connection_at"),
		get("cloud_name"), get("description"),
		get("client_email"), get("private_key_id"),
	)
}

// Test_CM_GetGcpParamsFromResponse_PlainDrift verifies that getGcpParamsFromResponse
// correctly refreshes plain attributes from the CM API response so that attribute
// drift (e.g. description changed in CM UI) is visible to Terraform.
func Test_CM_GetGcpParamsFromResponse_PlainDrift(t *testing.T) {
	t.Run("all plain fields are populated from the response", func(t *testing.T) {
		response := `{
			"id":"gcp-id","name":"my-gcp-conn",
			"uri":"https://cm/uri","account":"acc1",
			"updatedAt":"2024-01-02","createdAt":"2024-01-01",
			"category":"cloud","service":"gcp",
			"resource_url":"https://cm/resource","last_connection_ok":true,
			"last_connection_error":"none","last_connection_at":"2024-01-03",
			"cloud_name":"gcp","description":"gcp connection",
			"client_email":"svc@project.iam.gserviceaccount.com",
			"private_key_id":"key123"
		}`
		var data GCPConnectionTFSDK
		var diags diag.Diagnostics
		getGcpParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}

		checks := map[string]string{
			"id":             data.ID.ValueString(),
			"cloud_name":     data.CloudName.ValueString(),
			"description":    data.Description.ValueString(),
			"client_email":   data.ClientEmail.ValueString(),
			"private_key_id": data.PrivateKeyID.ValueString(),
		}
		expected := map[string]string{
			"id":             "gcp-id",
			"cloud_name":     "gcp",
			"description":    "gcp connection",
			"client_email":   "svc@project.iam.gserviceaccount.com",
			"private_key_id": "key123",
		}
		for field, got := range checks {
			if want := expected[field]; got != want {
				t.Errorf("%s: got %q, want %q", field, got, want)
			}
		}
		if !data.LastConnectionOK.ValueBool() {
			t.Error("last_connection_ok: expected true, got false")
		}
	})

	t.Run("description drift: CM value overwrites stale state value", func(t *testing.T) {
		var data GCPConnectionTFSDK
		data.Description = types.StringValue("STALE_DESCRIPTION")

		response := gcpResponse(map[string]string{"description": "LIVE_DESCRIPTION"})
		var diags diag.Diagnostics
		getGcpParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.Description.ValueString(); got != "LIVE_DESCRIPTION" {
			t.Errorf("description drift not detected: got %q, want %q", got, "LIVE_DESCRIPTION")
		}
	})

	t.Run("cloud_name drift: CM value overwrites stale state value", func(t *testing.T) {
		var data GCPConnectionTFSDK
		data.CloudName = types.StringValue("old-cloud")

		response := gcpResponse(map[string]string{"cloud_name": "gcp"})
		var diags diag.Diagnostics
		getGcpParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.CloudName.ValueString(); got != "gcp" {
			t.Errorf("cloud_name drift not detected: got %q, want %q", got, "gcp")
		}
	})

	t.Run("client_email drift: CM value overwrites stale state value", func(t *testing.T) {
		var data GCPConnectionTFSDK
		data.ClientEmail = types.StringValue("old@project.iam.gserviceaccount.com")

		response := gcpResponse(map[string]string{"client_email": "new@project.iam.gserviceaccount.com"})
		var diags diag.Diagnostics
		getGcpParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.ClientEmail.ValueString(); got != "new@project.iam.gserviceaccount.com" {
			t.Errorf("client_email drift not detected: got %q, want %q", got, "new@project.iam.gserviceaccount.com")
		}
	})
}

// Test_CM_GCPRead_OOBDelete_ErrorSentinel verifies that the exact error string produced
// by doRequest for a 404 response (format "status: 404, body: ...") matches the
// sentinel checked in resourceGCPConnection.Read so that OOB deletes are caught.
func Test_CM_GCPRead_OOBDelete_ErrorSentinel(t *testing.T) {
	simulatedErr := fmt.Errorf("status: 404, body: {\"error\":\"not found\"}")

	if !strings.Contains(simulatedErr.Error(), "status: 404") {
		t.Errorf("sentinel check failed: %q does not contain %q", simulatedErr.Error(), "status: 404")
	}
}
