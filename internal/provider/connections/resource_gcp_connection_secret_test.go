package connections

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_GcpConnectionSchema_KeyFileWriteOnly verifies that
// ciphertrust_gcp_connection.key_file is marked WriteOnly (never stored in state/plan
// artifacts, per the SecScan write-only hardening pass) and that key_file_version exists
// as the companion state-tracked rotation trigger.
func Test_GcpConnectionSchema_KeyFileWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceGCPConnection{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	keyFileAttr, ok := resp.Schema.Attributes["key_file"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected key_file attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["key_file"])
	}
	if !keyFileAttr.WriteOnly {
		t.Error("expected key_file schema attribute to be marked WriteOnly: true")
	}
	if !keyFileAttr.Sensitive {
		t.Error("expected key_file schema attribute to remain marked Sensitive: true")
	}
	if !keyFileAttr.Required {
		t.Error("expected key_file schema attribute to remain Required: true")
	}

	if _, ok := resp.Schema.Attributes["key_file_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected key_file_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["key_file_version"])
	}
}

// newGcpConnectionRawValue builds a tftypes.Value covering every attribute declared in
// resourceGCPConnection's Schema(), defaulting every attribute to null and applying the
// given overrides. Attribute types are derived from the schema itself.
func newGcpConnectionRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
	objType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	values := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for name, attrType := range objType.AttributeTypes {
		if v, ok := overrides[name]; ok {
			values[name] = v
			continue
		}
		values[name] = tftypes.NewValue(attrType, nil)
	}
	return tftypes.NewValue(objType, values)
}

// Test_GcpConnectionCreate_KeyFileReadFromConfigNotPlan proves that Create() reads
// key_file from req.Config rather than req.Plan, since the framework nulls WriteOnly
// attributes out of the plan before Create() ever runs.
func Test_GcpConnectionCreate_KeyFileReadFromConfigNotPlan(t *testing.T) {
	const wantKeyFile = `{"type":"service_account","project_id":"p1"}`

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/gcp/connections", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"gcp-id-1","uri":"u","account":"a","createdAt":"c","updatedAt":"u","category":"cat","service":"svc","resource_url":"ru"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceGCPConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name": tftypes.NewValue(tftypes.String, "my-gcp-conn"),
	}

	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["key_file"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newGcpConnectionRawValue(ctx, schemaResp, planOverrides)

	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["key_file"] = tftypes.NewValue(tftypes.String, wantKeyFile)
	configValue := newGcpConnectionRawValue(ctx, schemaResp, configOverrides)

	req := resource.CreateRequest{
		Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Create(): %v", resp.Diagnostics)
	}

	if !strings.Contains(capturedBody, `service_account`) || !strings.Contains(capturedBody, `p1`) {
		t.Errorf("expected request payload to contain the config-supplied key_file content, got body: %s", capturedBody)
	}

	var final GCPConnectionTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.KeyFile.IsNull() {
		t.Errorf("expected key_file to be null in state (write-only), got %q", final.KeyFile.ValueString())
	}
}

// Test_GcpConnectionUpdate_KeyFileVersionGatesResend proves that Update() only re-sends
// key_file to CM when key_file_version changes between state and plan. Since key_file is
// write-only (never stored in state), it cannot be diffed on its own — key_file_version is
// the explicit signal that the caller wants the current value re-sent.
func Test_GcpConnectionUpdate_KeyFileVersionGatesResend(t *testing.T) {
	const connID = "gcp-id-1"

	tests := []struct {
		name         string
		stateVersion int64
		planVersion  int64
		configKey    string
		expectInBody bool
	}{
		{
			name:         "version unchanged: key_file omitted from payload",
			stateVersion: 1,
			planVersion:  1,
			configKey:    `{"type":"service_account","project_id":"unused"}`,
			expectInBody: false,
		},
		{
			name:         "version bumped: key_file included from config",
			stateVersion: 1,
			planVersion:  2,
			configKey:    `{"type":"service_account","project_id":"rotated"}`,
			expectInBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedPatchBody string
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/connectionmgmt/services/gcp/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPatch {
					t.Fatalf("unexpected method %s", r.Method)
				}
				body, _ := io.ReadAll(r.Body)
				capturedPatchBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id":%q}`, connID)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := &common.Client{
				CipherTrustURL: server.URL,
				HTTPClient:     server.Client(),
				Log:            hclog.NewNullLogger(),
			}

			r := &resourceGCPConnection{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":       tftypes.NewValue(tftypes.String, connID),
				"name":     tftypes.NewValue(tftypes.String, "my-gcp-conn"),
				"key_file": tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["key_file_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newGcpConnectionRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["key_file_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newGcpConnectionRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["key_file"] = tftypes.NewValue(tftypes.String, tc.configKey)
			configOverrides["key_file_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newGcpConnectionRawValue(ctx, schemaResp, configOverrides)

			req := resource.UpdateRequest{
				Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
				Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
				State:  tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
			}
			resp := &resource.UpdateResponse{
				State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
			}

			r.Update(ctx, req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics from Update(): %v", resp.Diagnostics)
			}

			got := strings.Contains(capturedPatchBody, `"key_file"`)
			if got != tc.expectInBody {
				t.Errorf("expected key_file present in PATCH body = %v, got %v (body: %s)", tc.expectInBody, got, capturedPatchBody)
			}
			if tc.expectInBody && !strings.Contains(capturedPatchBody, `rotated`) {
				t.Errorf("expected PATCH body to contain the config-supplied key_file content, got: %s", capturedPatchBody)
			}

			var final GCPConnectionTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.KeyFile.IsNull() {
				t.Errorf("expected key_file to be null in state (write-only), got %q", final.KeyFile.ValueString())
			}
		})
	}
}
