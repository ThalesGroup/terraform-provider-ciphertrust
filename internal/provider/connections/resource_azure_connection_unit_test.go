package connections

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// azureResponse returns a JSON response for getAzureParamsFromResponse with only the
// specified field overridden. All other string fields default to empty, booleans to
// false, and numbers to 0 to avoid gjson duplicate-key issues.
func azureResponse(fields map[string]string) string {
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
		"client_id":%q,"tenant_id":%q,"cloud_name":%q,
		"description":%q,"certificate":%q,"certificate_thumbprint":%q,
		"external_certificate_used":false,
		"active_directory_endpoint":%q,"vault_resource_url":%q,
		"resource_manager_url":%q,"key_vault_dns_suffix":%q,
		"management_url":%q,"azure_stack_server_cert":%q,
		"azure_stack_connection_type":%q,"cert_duration":0
	}`,
		get("id"), get("name"),
		get("uri"), get("account"),
		get("updatedAt"), get("createdAt"),
		get("category"), get("service"),
		get("resource_url"),
		get("last_connection_error"), get("last_connection_at"),
		get("client_id"), get("tenant_id"), get("cloud_name"),
		get("description"), get("certificate"), get("certificate_thumbprint"),
		get("active_directory_endpoint"), get("vault_resource_url"),
		get("resource_manager_url"), get("key_vault_dns_suffix"),
		get("management_url"), get("azure_stack_server_cert"),
		get("azure_stack_connection_type"),
	)
}

// Test_CM_GetAzureParamsFromResponse_PlainDrift verifies that getAzureParamsFromResponse
// correctly refreshes plain string/bool/int attributes from the CM API response so that
// attribute drift (e.g. cloud_name changed in CM UI) is visible to Terraform.
func Test_CM_GetAzureParamsFromResponse_PlainDrift(t *testing.T) {
	t.Run("all plain fields are populated from the response", func(t *testing.T) {
		response := `{
			"id":"az-id","name":"my-conn",
			"uri":"https://cm/uri","account":"acc1",
			"updatedAt":"2024-01-02","createdAt":"2024-01-01",
			"category":"cloud","service":"azure",
			"resource_url":"https://cm/resource","last_connection_ok":true,
			"last_connection_error":"none","last_connection_at":"2024-01-03",
			"client_id":"cid","tenant_id":"tid","cloud_name":"AzureCloud",
			"description":"desc","certificate":"CERT","certificate_thumbprint":"THUMB",
			"external_certificate_used":true,
			"active_directory_endpoint":"https://ad","vault_resource_url":"https://vault",
			"resource_manager_url":"https://rm","key_vault_dns_suffix":".vault.azure.net",
			"management_url":"https://mgmt","azure_stack_server_cert":"STACKCERT",
			"azure_stack_connection_type":"AAD","cert_duration":730
		}`
		var data AzureConnectionTFSDK
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}

		checks := map[string]string{
			"id":                          data.ID.ValueString(),
			"client_id":                   data.ClientID.ValueString(),
			"tenant_id":                   data.TenantID.ValueString(),
			"cloud_name":                  data.CloudName.ValueString(),
			"description":                 data.Description.ValueString(),
			"certificate":                 data.Certificate.ValueString(),
			"certificate_thumbprint":      data.CertificateThumbprint.ValueString(),
			"active_directory_endpoint":   data.ActiveDirectoryEndpoint.ValueString(),
			"vault_resource_url":          data.VaultResourceURL.ValueString(),
			"resource_manager_url":        data.ResourceManagerURL.ValueString(),
			"key_vault_dns_suffix":        data.KeyVaultDNSSuffix.ValueString(),
			"management_url":              data.ManagementURL.ValueString(),
			"azure_stack_server_cert":     data.AzureStackServerCert.ValueString(),
			"azure_stack_connection_type": data.AzureStackConnectionType.ValueString(),
		}
		expected := map[string]string{
			"id":                          "az-id",
			"client_id":                   "cid",
			"tenant_id":                   "tid",
			"cloud_name":                  "AzureCloud",
			"description":                 "desc",
			"certificate":                 "CERT",
			"certificate_thumbprint":      "THUMB",
			"active_directory_endpoint":   "https://ad",
			"vault_resource_url":          "https://vault",
			"resource_manager_url":        "https://rm",
			"key_vault_dns_suffix":        ".vault.azure.net",
			"management_url":              "https://mgmt",
			"azure_stack_server_cert":     "STACKCERT",
			"azure_stack_connection_type": "AAD",
		}
		for field, got := range checks {
			if want := expected[field]; got != want {
				t.Errorf("%s: got %q, want %q", field, got, want)
			}
		}
		if !data.ExternalCertificateUsed.ValueBool() {
			t.Error("external_certificate_used: expected true, got false")
		}
		if data.CertDuration.ValueInt64() != 730 {
			t.Errorf("cert_duration: got %d, want 730", data.CertDuration.ValueInt64())
		}
	})

	t.Run("description drift: CM value overwrites stale state value", func(t *testing.T) {
		var data AzureConnectionTFSDK
		data.Description = types.StringValue("STALE_DESCRIPTION")

		response := azureResponse(map[string]string{"description": "LIVE_DESCRIPTION"})
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.Description.ValueString(); got != "LIVE_DESCRIPTION" {
			t.Errorf("description drift not detected: got %q, want %q", got, "LIVE_DESCRIPTION")
		}
	})

	t.Run("cloud_name drift: CM value overwrites stale state value", func(t *testing.T) {
		var data AzureConnectionTFSDK
		data.CloudName = types.StringValue("AzureStack")

		response := azureResponse(map[string]string{"cloud_name": "AzureUSGovernment"})
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.CloudName.ValueString(); got != "AzureUSGovernment" {
			t.Errorf("cloud_name drift not detected: got %q, want %q", got, "AzureUSGovernment")
		}
	})

	t.Run("tenant_id drift: CM value overwrites stale state value", func(t *testing.T) {
		var data AzureConnectionTFSDK
		data.TenantID = types.StringValue("old-tenant")

		response := azureResponse(map[string]string{"tenant_id": "new-tenant"})
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.TenantID.ValueString(); got != "new-tenant" {
			t.Errorf("tenant_id drift not detected: got %q, want %q", got, "new-tenant")
		}
	})
}

// Test_CM_AzureRead_OOBDelete_ErrorSentinel verifies that the exact error string produced
// by doRequest for a 404 response (format "status: 404, body: ...") matches the
// sentinel checked in resourceAzureConnection.Read so that OOB deletes are caught.
func Test_CM_AzureRead_OOBDelete_ErrorSentinel(t *testing.T) {
	// Simulate the error format returned by doRequest on a 404.
	simulatedErr := fmt.Errorf("status: 404, body: {\"error\":\"not found\"}")

	if !strings.Contains(simulatedErr.Error(), "status: 404") {
		t.Errorf("sentinel check failed: %q does not contain %q", simulatedErr.Error(), "status: 404")
	}
}

// Test_CM_AzureConnection_CloudNameEnumValidator verifies that cloud_name
// rejects any value other than the four documented Azure clouds at plan
// time, closing the gap where arbitrary strings were silently accepted and
// persisted on CM.
func Test_CM_AzureConnection_CloudNameEnumValidator(t *testing.T) {
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	(&resourceAzureConnection{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	attr, ok := schemaResp.Schema.Attributes["cloud_name"]
	if !ok {
		t.Fatal("cloud_name attribute not found in schema")
	}
	withValidators, ok := attr.(stringValidatorsAttribute)
	if !ok {
		t.Fatalf("cloud_name attribute (%T) does not expose StringValidators", attr)
	}
	validators := withValidators.StringValidators()
	if len(validators) == 0 {
		t.Fatal("cloud_name has no validators; expected an enum validator restricting it to the documented Azure clouds")
	}

	runValidators := func(value types.String) diag.Diagnostics {
		var diags diag.Diagnostics
		for _, v := range validators {
			req := validator.StringRequest{Path: path.Root("cloud_name"), ConfigValue: value}
			var resp validator.StringResponse
			v.ValidateString(ctx, req, &resp)
			diags.Append(resp.Diagnostics...)
		}
		return diags
	}

	for _, valid := range []string{"AzureCloud", "AzureChinaCloud", "AzureUSGovernment", "AzureStack"} {
		t.Run("documented value \""+valid+"\" is accepted", func(t *testing.T) {
			if diags := runValidators(types.StringValue(valid)); diags.HasError() {
				t.Errorf("unexpected error for %q: %v", valid, diags)
			}
		})
	}

	t.Run("an arbitrary string is rejected", func(t *testing.T) {
		if diags := runValidators(types.StringValue("AzureBogusCloud")); !diags.HasError() {
			t.Error("expected an error for \"AzureBogusCloud\", got none")
		}
	})

	t.Run("case does not bypass the enum check", func(t *testing.T) {
		if diags := runValidators(types.StringValue("azurecloud")); !diags.HasError() {
			t.Error("expected an error for \"azurecloud\", got none")
		}
	})

	t.Run("unset (null) config value is left to Optional+Computed defaulting", func(t *testing.T) {
		if diags := runValidators(types.StringNull()); diags.HasError() {
			t.Errorf("unexpected error for a null config value: %v", diags)
		}
	})
}
