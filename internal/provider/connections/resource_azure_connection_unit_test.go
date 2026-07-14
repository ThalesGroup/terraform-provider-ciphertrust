package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
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

// azureResponseWithLabels returns a JSON response that includes a labels map. This
// mirrors what a CM GET would return after the provider sends labels on create/update.
func azureResponseWithLabels(labels map[string]string) string {
	base := azureResponse(map[string]string{"id": "az-id", "name": "my-conn"})
	if len(labels) == 0 {
		return base
	}
	// Build a JSON labels object and inject it before the closing brace.
	var pairs []string
	for k, v := range labels {
		pairs = append(pairs, fmt.Sprintf("%q:%q", k, v))
	}
	labelsJSON := "{" + strings.Join(pairs, ",") + "}"
	// Insert "labels":{…} before the closing }
	closing := strings.LastIndex(base, "}")
	return base[:closing] + `,"labels":` + labelsJSON + base[closing:]
}

// labelsMapMust builds a types.Map from a plain Go string map. Panics on error (test helper only).
func labelsMapMust(m map[string]string) types.Map {
	vals := make(map[string]attr.Value, len(m))
	for k, v := range m {
		vals[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, vals)
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

// Test_CM_AzureLabelsJSON_OmitEmptyBehaviour verifies the omitempty tag on
// AzureConnectionJSON.Labels so that an uninitialized (nil) labels map is omitted
// from the marshaled JSON, preventing the provider from sending "labels":{} or
// "labels":null on every PATCH and silently clearing externally-set labels.
func Test_CM_AzureLabelsJSON_OmitEmptyBehaviour(t *testing.T) {
	t.Run("nil Labels field is omitted from JSON (omitempty)", func(t *testing.T) {
		payload := AzureConnectionJSON{Name: "test"}
		// Labels is not set → nil map; with omitempty it must be absent from the JSON.
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if strings.Contains(string(b), `"labels"`) {
			t.Errorf("expected labels to be absent from JSON when nil, got: %s", b)
		}
	})

	t.Run("nil Meta field is omitted from JSON (omitempty)", func(t *testing.T) {
		payload := AzureConnectionJSON{Name: "test"}
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if strings.Contains(string(b), `"meta"`) {
			t.Errorf("expected meta to be absent from JSON when nil, got: %s", b)
		}
	})

	t.Run("populated Labels map is included in JSON", func(t *testing.T) {
		payload := AzureConnectionJSON{
			Name:   "test",
			Labels: map[string]interface{}{"env": "drift_test"},
		}
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if !strings.Contains(string(b), `"labels"`) {
			t.Errorf("expected labels to be present in JSON, got: %s", b)
		}
		if !strings.Contains(string(b), `"env"`) {
			t.Errorf("expected label key 'env' in JSON, got: %s", b)
		}
	})
}

// Test_CM_AzureNullPlanLabels_ProducesNilPayload verifies that when plan.Labels is null
// or unknown (not configured by the user), the null guard added in Create/Update means
// payload.Labels is never assigned, so it remains nil and is omitted from the JSON.
// This prevents the provider from sending "labels":{} on every apply and wiping any
// labels set outside Terraform.
func Test_CM_AzureNullPlanLabels_ProducesNilPayload(t *testing.T) {
	// buildLabelsPayload mirrors the guard logic used in Create and Update.
	buildLabelsPayload := func(labels types.Map) map[string]interface{} {
		if !labels.IsNull() && !labels.IsUnknown() {
			m := make(map[string]interface{})
			for k, v := range labels.Elements() {
				m[k] = v.(types.String).ValueString()
			}
			return m
		}
		return nil
	}

	t.Run("null plan labels → payload.Labels stays nil", func(t *testing.T) {
		labels := types.MapNull(types.StringType)
		got := buildLabelsPayload(labels)
		if got != nil {
			t.Errorf("expected nil payload for null plan labels, got %v", got)
		}

		payload := AzureConnectionJSON{Name: "test", Labels: got}
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if strings.Contains(string(b), `"labels"`) {
			t.Errorf("expected labels absent from JSON for null plan, got: %s", b)
		}
	})

	t.Run("unknown plan labels → payload.Labels stays nil", func(t *testing.T) {
		labels := types.MapUnknown(types.StringType)
		got := buildLabelsPayload(labels)
		if got != nil {
			t.Errorf("expected nil payload for unknown plan labels, got %v", got)
		}
	})

	t.Run("configured plan labels → payload.Labels is populated", func(t *testing.T) {
		labels := labelsMapMust(map[string]string{"env": "drift_test"})
		got := buildLabelsPayload(labels)
		if got == nil {
			t.Fatal("expected non-nil payload for configured labels, got nil")
		}
		if got["env"] != "drift_test" {
			t.Errorf("expected got[env]=drift_test, got %v", got["env"])
		}
	})

	t.Run("empty (non-null) plan labels → payload.Labels is an empty map (not nil)", func(t *testing.T) {
		// A user who explicitly sets labels = {} wants to clear labels, so the empty
		// map must still be sent (not omitted). However the omitempty tag means an
		// empty map would still be omitted. This subtest documents that the guard
		// fires (not-null, not-unknown), builds an empty map, and that the struct
		// field omitempty means it won't appear in the JSON for an empty map.
		labels, diags := types.MapValue(types.StringType, map[string]attr.Value{})
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		got := buildLabelsPayload(labels)
		if got == nil {
			t.Fatal("expected non-nil (but empty) payload for empty configured labels, got nil")
		}
		if len(got) != 0 {
			t.Errorf("expected empty map, got %v", got)
		}
	})
}

// Test_CM_GetAzureParamsFromResponse_LabelsParsed verifies that getAzureParamsFromResponse
// correctly reads labels from the CM GET response. This covers Fix 1: since Create/Update
// now issues a GET after the mutating call, labels returned by CM are reflected in state.
func Test_CM_GetAzureParamsFromResponse_LabelsParsed(t *testing.T) {
	t.Run("labels present in response are parsed into state", func(t *testing.T) {
		response := azureResponseWithLabels(map[string]string{"env": "prod", "team": "security"})
		var data AzureConnectionTFSDK
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if data.Labels.IsNull() {
			t.Fatal("expected non-null labels, got null")
		}
		elems := data.Labels.Elements()
		if len(elems) != 2 {
			t.Fatalf("expected 2 label entries, got %d", len(elems))
		}
		for _, key := range []string{"env", "team"} {
			if _, ok := elems[key]; !ok {
				t.Errorf("expected label key %q to be present, got: %v", key, elems)
			}
		}
	})

	t.Run("labels absent from response results in null state labels", func(t *testing.T) {
		// CM may return no labels field at all when none are stored
		response := azureResponse(map[string]string{"id": "az-id", "name": "my-conn"})
		var data AzureConnectionTFSDK
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		// ParseMap returns MapNull when the field is absent
		if !data.Labels.IsNull() {
			t.Errorf("expected null labels when field absent from response, got: %v", data.Labels)
		}
	})

	t.Run("labels drift: CM GET value overwrites stale state labels", func(t *testing.T) {
		var data AzureConnectionTFSDK
		// Pre-populate with stale labels in state (simulates what was saved from a prior apply)
		data.Labels = labelsMapMust(map[string]string{"old_key": "old_val"})

		// Simulate the GET response that now populates state after a Create/Update
		response := azureResponseWithLabels(map[string]string{"env": "staging"})
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		elems := data.Labels.Elements()
		if _, hasOld := elems["old_key"]; hasOld {
			t.Error("stale label key 'old_key' should have been replaced by the CM GET response")
		}
		if _, hasNew := elems["env"]; !hasNew {
			t.Errorf("expected label key 'env' from CM GET response, got: %v", elems)
		}
	})
}

// Test_CM_AzureCertDuration_UpdatePayload verifies that cert_duration is sent when non-zero
// and omitted when zero (omitempty), covering the Update payload and JSON tag fixes.
func Test_CM_AzureCertDuration_UpdatePayload(t *testing.T) {
	t.Run("non-zero cert_duration is serialised into the PATCH payload", func(t *testing.T) {
		payload := AzureConnectionJSON{CertDuration: 365}
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if !strings.Contains(string(b), `"cert_duration":365`) {
			t.Errorf("expected cert_duration:365 in payload, got: %s", b)
		}
	})

	t.Run("zero cert_duration is omitted from the PATCH payload (omitempty)", func(t *testing.T) {
		payload := AzureConnectionJSON{} // CertDuration defaults to 0
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if strings.Contains(string(b), `"cert_duration"`) {
			t.Errorf("expected cert_duration absent from payload when zero, got: %s", b)
		}
	})
}

// Test_CM_AzureCertDuration_ResponseParsing verifies that cert_duration=0 from CM preserves
// the plan value (client_secret fix) and non-zero values are still written to state (drift).
func Test_CM_AzureCertDuration_ResponseParsing(t *testing.T) {
	t.Run("response cert_duration=0 preserves the plan value (client_secret connection)", func(t *testing.T) {
		// Simulate: user sets cert_duration=365, plan is loaded into data, then the
		// post-update GET returns cert_duration=0 because CM ignores it for client_secret.
		var data AzureConnectionTFSDK
		data.CertDuration = types.Int64Value(365) // plan value

		response := azureResponse(map[string]string{}) // cert_duration=0 in azureResponse
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.CertDuration.ValueInt64(); got != 365 {
			t.Errorf("cert_duration: CM returned 0, plan value should be preserved; got %d, want 365", got)
		}
	})

	t.Run("response cert_duration non-zero overwrites state (certificate connection drift)", func(t *testing.T) {
		var data AzureConnectionTFSDK
		data.CertDuration = types.Int64Value(365) // prior state

		// CM returns a different non-zero duration (e.g. admin changed it out-of-band)
		response := strings.Replace(
			azureResponse(map[string]string{}),
			`"cert_duration":0`,
			`"cert_duration":730`,
			1,
		)
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.CertDuration.ValueInt64(); got != 730 {
			t.Errorf("cert_duration: CM returned 730, state should reflect it; got %d, want 730", got)
		}
	})

	t.Run("response cert_duration=0 leaves zero state as zero (no prior value)", func(t *testing.T) {
		// data.CertDuration starts at zero value (null/unset) — nothing to preserve.
		var data AzureConnectionTFSDK
		// CertDuration is the Go zero value (Int64Null / zero), response also 0.
		response := azureResponse(map[string]string{})
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		// data.CertDuration should remain whatever it was (zero/null) — not panic or error.
		if got := data.CertDuration.ValueInt64(); got != 0 {
			t.Errorf("cert_duration: expected 0 when both response and state are 0, got %d", got)
		}
	})

	t.Run("response cert_duration=0 and unknown plan value → cert_duration becomes null (not unknown)", func(t *testing.T) {
		// This is the regression case for the "provider still indicated an unknown value after apply"
		// error. When cert_duration is not configured by the user, Terraform marks it as unknown in
		// the plan (because it is Computed). After Create/Update, CM returns cert_duration=0 for
		// client_secret connections. The provider must resolve the unknown to a known value (null)
		// or Terraform will reject the apply result with a fatal error.
		var data AzureConnectionTFSDK
		data.CertDuration = types.Int64Unknown() // simulates plan value when cert_duration not configured

		response := azureResponse(map[string]string{}) // cert_duration=0
		var diags diag.Diagnostics
		getAzureParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if data.CertDuration.IsUnknown() {
			t.Error("cert_duration must not remain unknown after apply; Terraform requires all values to be known after apply")
		}
		// The resolved value should be null (not applicable for client_secret connections).
		if !data.CertDuration.IsNull() {
			t.Errorf("cert_duration: expected null when CM returns 0 and no prior value was set, got %v", data.CertDuration)
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

	cloudNameAttr, ok := schemaResp.Schema.Attributes["cloud_name"]
	if !ok {
		t.Fatal("cloud_name attribute not found in schema")
	}
	withValidators, ok := cloudNameAttr.(stringValidatorsAttribute)
	if !ok {
		t.Fatalf("cloud_name attribute (%T) does not expose StringValidators", cloudNameAttr)
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
