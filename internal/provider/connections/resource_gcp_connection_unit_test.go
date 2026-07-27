package connections

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
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

// Test_CM_GCPRead_OOBDelete_GracefulStateRemoval is an end-to-end unit test that
// proves Read() silently removes the resource from state — instead of returning an
// error diagnostic — when CM responds with 404.  This is the out-of-band deletion
// scenario described in TFIN-326: after an OOB delete the next terraform plan must
// propose a clean +create rather than hard-erroring.
//
// The test uses net/http/httptest as a drop-in fake CM so no live endpoint is needed.
func Test_CM_GCPRead_OOBDelete_GracefulStateRemoval(t *testing.T) {
	// Arrange: fake CM always returns 404 Not Found.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintln(w, `{"code":16,"codeDesc":"NCERRResourceNotFound: Resource not found"}`)
	}))
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceGCPConnection{client: client}
	ctx := context.Background()

	// Build the schema so we can construct a properly-typed tfsdk.State.
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	// Construct a tftypes.Value representing a previously-stored connection state.
	// Every attribute declared in the schema must appear in the map.
	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		// GCP-specific attributes
		"id":             tftypes.NewValue(tftypes.String, "nonexistent-gcp-id"),
		"name":           tftypes.NewValue(tftypes.String, "my-gcp-conn"),
		"key_file":       tftypes.NewValue(tftypes.String, `{"type":"service_account"}`),
		"description":    tftypes.NewValue(tftypes.String, ""),
		"cloud_name":     tftypes.NewValue(tftypes.String, "gcp"),
		"client_email":   tftypes.NewValue(tftypes.String, ""),
		"private_key_id": tftypes.NewValue(tftypes.String, ""),
		// Common response attributes (from CMCreateConnectionResponseCommonTFSDK)
		"uri":                   tftypes.NewValue(tftypes.String, ""),
		"account":               tftypes.NewValue(tftypes.String, ""),
		"created_at":            tftypes.NewValue(tftypes.String, ""),
		"updated_at":            tftypes.NewValue(tftypes.String, ""),
		"service":               tftypes.NewValue(tftypes.String, ""),
		"category":              tftypes.NewValue(tftypes.String, ""),
		"resource_url":          tftypes.NewValue(tftypes.String, ""),
		"last_connection_ok":    tftypes.NewValue(tftypes.Bool, false),
		"last_connection_error": tftypes.NewValue(tftypes.String, ""),
		"last_connection_at":    tftypes.NewValue(tftypes.String, ""),
		// Collection attributes
		"products": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
		"labels":   tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{}),
		"meta":     tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{}),
	})

	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    rawState,
		},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    rawState,
		},
	}

	// Act: simulate a terraform plan/refresh after the connection was deleted out-of-band.
	r.Read(ctx, req, resp)

	// Assert 1: Read() must NOT add any error diagnostic on 404.
	if resp.Diagnostics.HasError() {
		t.Errorf("Read() must not add error diagnostics on OOB-delete 404, got: %v",
			resp.Diagnostics)
	}

	// Assert 2: Read() must add a Warning diagnostic on 404 as per the State Preserved standard.
	if len(resp.Diagnostics) == 0 {
		t.Error("Read() must add a Warning diagnostic on OOB-delete 404 to notify state preservation")
	}

	// Assert 3: Read() must NOT remove the resource from state (state.Raw.IsNull must be false) on 404.
	if resp.State.Raw.IsNull() {
		t.Errorf("Read() must preserve the resource in state (state.Raw.IsNull is false) on 404 as per CLAUDE.md convention, got null state")
	}
}

// Test_CM_GetGcpKeyFile_ResolvesInlineOrFileContent verifies getGcpKeyFile's
// behavior across inline JSON, whitespace, and filesystem paths (existing,
// empty, and nonexistent), since that resolution feeds the empty-value check
// added to Create/Update to prevent a silent no-op on an empty key_file.
func Test_CM_GetGcpKeyFile_ResolvesInlineOrFileContent(t *testing.T) {
	ctx := context.Background()

	t.Run("empty string resolves to empty", func(t *testing.T) {
		if got := getGcpKeyFile(ctx, ""); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("whitespace-only string resolves to empty", func(t *testing.T) {
		if got := getGcpKeyFile(ctx, "   \t\n  "); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("inline JSON that is not a filesystem path passes through verbatim", func(t *testing.T) {
		inline := `{"type":"service_account","client_email":"svc@project.iam.gserviceaccount.com"}`
		if got := getGcpKeyFile(ctx, inline); got != inline {
			t.Errorf("got %q, want %q", got, inline)
		}
	})

	t.Run("path to an existing non-empty file returns its content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key.json")
		content := `{"type":"service_account","client_email":"svc@project.iam.gserviceaccount.com"}`
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write test key file: %v", err)
		}
		if got := getGcpKeyFile(ctx, path); got != content {
			t.Errorf("got %q, want %q", got, content)
		}
	})

	t.Run("path to an existing but empty file returns empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte(""), 0600); err != nil {
			t.Fatalf("failed to write test key file: %v", err)
		}
		if got := getGcpKeyFile(ctx, path); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("path to a nonexistent file passes the raw path through verbatim", func(t *testing.T) {
		path := "/nonexistent/path/to/key.json"
		if got := getGcpKeyFile(ctx, path); got != path {
			t.Errorf("got %q, want %q", got, path)
		}
	})
}

// Test_CM_ResolveGcpKeyFile_RejectsEmptyResolvedValue verifies that
// resolveGcpKeyFile returns an error instead of an empty resolved value for
// every input that getGcpKeyFile collapses to "", closing the silent no-op
// gap left by validating only the raw key_file string at plan time.
func Test_CM_ResolveGcpKeyFile_RejectsEmptyResolvedValue(t *testing.T) {
	ctx := context.Background()

	t.Run("empty string is rejected", func(t *testing.T) {
		resolved, errMsg := resolveGcpKeyFile(ctx, "")
		if errMsg == "" {
			t.Fatalf("expected an error message, got none (resolved=%q)", resolved)
		}
		if resolved != "" {
			t.Errorf("expected empty resolved value on error, got %q", resolved)
		}
	})

	t.Run("whitespace-only string is rejected", func(t *testing.T) {
		resolved, errMsg := resolveGcpKeyFile(ctx, "   ")
		if errMsg == "" {
			t.Fatalf("expected an error message, got none (resolved=%q)", resolved)
		}
		if resolved != "" {
			t.Errorf("expected empty resolved value on error, got %q", resolved)
		}
	})

	t.Run("path to an existing but empty file is rejected", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte(""), 0600); err != nil {
			t.Fatalf("failed to write test key file: %v", err)
		}
		resolved, errMsg := resolveGcpKeyFile(ctx, path)
		if errMsg == "" {
			t.Fatalf("expected an error message, got none (resolved=%q)", resolved)
		}
		if resolved != "" {
			t.Errorf("expected empty resolved value on error, got %q", resolved)
		}
	})

	t.Run("non-empty inline JSON resolves without error", func(t *testing.T) {
		inline := `{"type":"service_account","client_email":"svc@project.iam.gserviceaccount.com"}`
		resolved, errMsg := resolveGcpKeyFile(ctx, inline)
		if errMsg != "" {
			t.Fatalf("unexpected error message: %q", errMsg)
		}
		if resolved != inline {
			t.Errorf("got %q, want %q", resolved, inline)
		}
	})

	t.Run("path to an existing non-empty file resolves without error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key.json")
		content := `{"type":"service_account","client_email":"svc@project.iam.gserviceaccount.com"}`
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write test key file: %v", err)
		}
		resolved, errMsg := resolveGcpKeyFile(ctx, path)
		if errMsg != "" {
			t.Fatalf("unexpected error message: %q", errMsg)
		}
		if resolved != content {
			t.Errorf("got %q, want %q", resolved, content)
		}
	})
}

// stringValidatorsAttribute is satisfied by schema.StringAttribute; used to pull
// the configured Validators back out of the built schema without depending on
// the concrete attribute struct.
type stringValidatorsAttribute interface {
	StringValidators() []validator.String
}

// Test_CM_GCPConnection_CloudNameEnumValidator verifies that cloud_name rejects
// any value other than "gcp" at plan time (the schema's Validators, exercised
// directly), closing the gap where arbitrary strings were silently accepted
// and persisted on CM.
func Test_CM_GCPConnection_CloudNameEnumValidator(t *testing.T) {
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	(&resourceGCPConnection{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
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
		t.Fatal("cloud_name has no validators; expected an enum validator restricting it to \"gcp\"")
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

	t.Run("the only documented valid value is accepted", func(t *testing.T) {
		if diags := runValidators(types.StringValue("gcp")); diags.HasError() {
			t.Errorf("unexpected error for \"gcp\": %v", diags)
		}
	})

	t.Run("an arbitrary string is rejected", func(t *testing.T) {
		if diags := runValidators(types.StringValue("gcp-invalid")); !diags.HasError() {
			t.Error("expected an error for \"gcp-invalid\", got none")
		}
	})

	t.Run("case does not bypass the enum check", func(t *testing.T) {
		if diags := runValidators(types.StringValue("GCP")); !diags.HasError() {
			t.Error("expected an error for \"GCP\", got none")
		}
	})

	t.Run("unset (null) config value is left to Optional+Computed defaulting", func(t *testing.T) {
		if diags := runValidators(types.StringNull()); diags.HasError() {
			t.Errorf("unexpected error for a null config value: %v", diags)
		}
	})
}
