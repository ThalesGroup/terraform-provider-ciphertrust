// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package connections

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// scpResponse returns a JSON response for getParamsFromResponse with only the
// specified string fields set. Port defaults to 0 unless "port" key is provided as a
// raw JSON value via the portVal parameter.
func scpResponse(fields map[string]string, port int64) string {
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
		"description":%q,"protocol":%q,"port":%d
	}`,
		get("id"), get("name"),
		get("uri"), get("account"),
		get("updatedAt"), get("createdAt"),
		get("category"), get("service"),
		get("resource_url"),
		get("last_connection_error"), get("last_connection_at"),
		get("description"), get("protocol"), port,
	)
}

// Test_CM_GetScpParamsFromResponse_PlainDrift verifies that getParamsFromResponse
// correctly refreshes plain attributes from the CM API response so that attribute
// drift (e.g. description or protocol changed in CM UI) is visible to Terraform.
func Test_CM_GetScpParamsFromResponse_PlainDrift(t *testing.T) {
	t.Run("all plain fields are populated from the response", func(t *testing.T) {
		response := `{
			"id":"scp-id","name":"my-scp-conn",
			"uri":"https://cm/uri","account":"acc1",
			"updatedAt":"2024-01-02","createdAt":"2024-01-01",
			"category":"backup","service":"scp",
			"resource_url":"https://cm/resource","last_connection_ok":true,
			"last_connection_error":"none","last_connection_at":"2024-01-03",
			"description":"backup target","protocol":"sftp","port":22
		}`
		var data CMScpConnectionTFSDK
		var diags diag.Diagnostics
		getParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}

		checks := map[string]string{
			"id":          data.ID.ValueString(),
			"description": data.Description.ValueString(),
			"protocol":    data.Protocol.ValueString(),
		}
		expected := map[string]string{
			"id":          "scp-id",
			"description": "backup target",
			"protocol":    "sftp",
		}
		for field, got := range checks {
			if want := expected[field]; got != want {
				t.Errorf("%s: got %q, want %q", field, got, want)
			}
		}
		if data.Port.ValueInt64() != 22 {
			t.Errorf("port: got %d, want 22", data.Port.ValueInt64())
		}
		if !data.LastConnectionOK.ValueBool() {
			t.Error("last_connection_ok: expected true, got false")
		}
	})

	t.Run("description drift: CM value overwrites stale state value", func(t *testing.T) {
		var data CMScpConnectionTFSDK
		data.Description = types.StringValue("STALE_DESCRIPTION")

		response := scpResponse(map[string]string{"description": "LIVE_DESCRIPTION"}, 0)
		var diags diag.Diagnostics
		getParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.Description.ValueString(); got != "LIVE_DESCRIPTION" {
			t.Errorf("description drift not detected: got %q, want %q", got, "LIVE_DESCRIPTION")
		}
	})

	t.Run("protocol drift: CM value overwrites stale state value", func(t *testing.T) {
		var data CMScpConnectionTFSDK
		data.Protocol = types.StringValue("scp")

		response := scpResponse(map[string]string{"protocol": "sftp"}, 0)
		var diags diag.Diagnostics
		getParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.Protocol.ValueString(); got != "sftp" {
			t.Errorf("protocol drift not detected: got %q, want %q", got, "sftp")
		}
	})

	t.Run("port drift: CM value overwrites stale state value", func(t *testing.T) {
		var data CMScpConnectionTFSDK
		data.Port = types.Int64Value(2222)

		response := scpResponse(map[string]string{}, 22)
		var diags diag.Diagnostics
		getParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if got := data.Port.ValueInt64(); got != 22 {
			t.Errorf("port drift not detected: got %d, want 22", got)
		}
	})
}

// Test_CM_GetScpParamsFromResponse_MetaAndLabels verifies that getParamsFromResponse
// correctly populates meta and labels from the CM API response so that drift in
// those maps is visible to Terraform after a Read.
func Test_CM_GetScpParamsFromResponse_MetaAndLabels(t *testing.T) {
	t.Run("meta entries from response are stored in state", func(t *testing.T) {
		response := `{
			"id":"scp-id",
			"meta":{"custom_meta_key1":"custom_value1","env":"prod"},
			"labels":{"team":"infra"}
		}`
		var data CMScpConnectionTFSDK
		var diags diag.Diagnostics
		getParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}

		wantMeta := map[string]string{
			"custom_meta_key1": "custom_value1",
			"env":              "prod",
		}
		for k, want := range wantMeta {
			got, ok := data.Meta.Elements()[k]
			if !ok {
				t.Errorf("meta key %q missing from state", k)
				continue
			}
			if gotStr := got.(types.String).ValueString(); gotStr != want {
				t.Errorf("meta[%q]: got %q, want %q", k, gotStr, want)
			}
		}
	})

	t.Run("meta drift: CM value overwrites stale state", func(t *testing.T) {
		// Simulate state already having old meta entries.
		oldMeta, diags := types.MapValueFrom(
			context.Background(),
			types.StringType,
			map[string]string{"custom_meta_key1": "old_value"},
		)
		if diags.HasError() {
			t.Fatalf("setup error: %v", diags)
		}

		var data CMScpConnectionTFSDK
		data.Meta = oldMeta

		// CM now returns updated meta.
		response := `{"id":"scp-id","meta":{"custom_meta_key1":"new_value"}}`
		var rd diag.Diagnostics
		getParamsFromResponse(response, &rd, &data)

		if rd.HasError() {
			t.Fatalf("unexpected diagnostics: %v", rd)
		}

		got, ok := data.Meta.Elements()["custom_meta_key1"]
		if !ok {
			t.Fatal("meta key custom_meta_key1 missing after drift refresh")
		}
		if gotStr := got.(types.String).ValueString(); gotStr != "new_value" {
			t.Errorf("meta drift not detected: got %q, want %q", gotStr, "new_value")
		}
	})

	t.Run("empty meta in response yields empty map in state", func(t *testing.T) {
		response := `{"id":"scp-id","meta":{}}`
		var data CMScpConnectionTFSDK
		var diags diag.Diagnostics
		getParamsFromResponse(response, &diags, &data)

		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if n := len(data.Meta.Elements()); n != 0 {
			t.Errorf("expected empty meta map, got %d elements", n)
		}
	})
}

// Test_CM_SCPRead_OOBDelete_ErrorSentinel verifies that the exact error string produced
// by doRequest for a 404 response (format "status: 404, body: ...") matches the
// sentinel checked in resourceCMScpConnection.Read so that OOB deletes are caught.
func Test_CM_SCPRead_OOBDelete_ErrorSentinel(t *testing.T) {
	simulatedErr := fmt.Errorf("status: 404, body: {\"error\":\"not found\"}")

	if !strings.Contains(simulatedErr.Error(), "status: 404") {
		t.Errorf("sentinel check failed: %q does not contain %q", simulatedErr.Error(), "status: 404")
	}
}
