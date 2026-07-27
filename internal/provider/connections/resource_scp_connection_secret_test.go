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

// Test_ScpConnectionSchema_PasswordWriteOnly verifies that
// ciphertrust_scp_connection.password is marked WriteOnly (never stored in
// state/plan artifacts, per the SecScan write-only hardening pass) and that
// password_version exists as the companion state-tracked rotation trigger.
func Test_ScpConnectionSchema_PasswordWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCMScpConnection{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	passwordAttr, ok := resp.Schema.Attributes["password"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected password attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["password"])
	}
	if !passwordAttr.WriteOnly {
		t.Error("expected password schema attribute to be marked WriteOnly: true")
	}
	if !passwordAttr.Sensitive {
		t.Error("expected password schema attribute to remain marked Sensitive: true")
	}
	if passwordAttr.Computed {
		t.Error("expected password schema attribute to not be Computed (WriteOnly attributes cannot be Computed)")
	}

	if _, ok := resp.Schema.Attributes["password_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected password_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["password_version"])
	}
}

// newScpConnectionRawValue builds a tftypes.Value covering every attribute declared in
// resourceCMScpConnection's Schema(), defaulting every attribute to null and applying the
// given overrides. Attribute types are derived from the schema itself.
func newScpConnectionRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_ScpConnectionCreate_PasswordReadFromConfigNotPlan proves that Create() reads
// password from req.Config rather than req.Plan, since the framework nulls WriteOnly
// attributes out of the plan before Create() ever runs.
func Test_ScpConnectionCreate_PasswordReadFromConfigNotPlan(t *testing.T) {
	const wantPassword = "hunter2-scp"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/scp/connections", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"scp-id-1","uri":"u","account":"a","createdAt":"c","updatedAt":"u","category":"cat","service":"svc","resource_url":"ru"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMScpConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":        tftypes.NewValue(tftypes.String, "my-scp"),
		"auth_method": tftypes.NewValue(tftypes.String, "password"),
		"host":        tftypes.NewValue(tftypes.String, "scp.example.com"),
		"path_to":     tftypes.NewValue(tftypes.String, "/data"),
		"public_key":  tftypes.NewValue(tftypes.String, "ssh-rsa AAAA"),
		"username":    tftypes.NewValue(tftypes.String, "svc-user"),
	}

	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["password"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newScpConnectionRawValue(ctx, schemaResp, planOverrides)

	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["password"] = tftypes.NewValue(tftypes.String, wantPassword)
	configValue := newScpConnectionRawValue(ctx, schemaResp, configOverrides)

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

	if want := fmt.Sprintf(`"password":%q`, wantPassword); !strings.Contains(capturedBody, want) {
		t.Errorf("expected request payload to contain %s (read from config), got body: %s", want, capturedBody)
	}

	var final CMScpConnectionTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.Password.IsNull() {
		t.Errorf("expected password to be null in state (write-only), got %q", final.Password.ValueString())
	}
}

// Test_ScpConnectionUpdate_PasswordVersionGatesResend proves that Update() only re-sends
// password to CM when password_version changes between state and plan. Since password is
// write-only (never stored in state), it cannot be diffed on its own — password_version is
// the explicit signal that the caller wants the current value re-sent.
func Test_ScpConnectionUpdate_PasswordVersionGatesResend(t *testing.T) {
	const connID = "scp-id-1"

	tests := []struct {
		name         string
		stateVersion int64
		planVersion  int64
		configPass   string
		expectInBody bool
	}{
		{
			name:         "version unchanged: password omitted from payload",
			stateVersion: 1,
			planVersion:  1,
			configPass:   "unused-password",
			expectInBody: false,
		},
		{
			name:         "version bumped: password included from config",
			stateVersion: 1,
			planVersion:  2,
			configPass:   "rotated-password",
			expectInBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedPatchBody string
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/connectionmgmt/services/scp/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
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

			r := &resourceCMScpConnection{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":          tftypes.NewValue(tftypes.String, connID),
				"name":        tftypes.NewValue(tftypes.String, "my-scp"),
				"auth_method": tftypes.NewValue(tftypes.String, "password"),
				"host":        tftypes.NewValue(tftypes.String, "scp.example.com"),
				"path_to":     tftypes.NewValue(tftypes.String, "/data"),
				"public_key":  tftypes.NewValue(tftypes.String, "ssh-rsa AAAA"),
				"username":    tftypes.NewValue(tftypes.String, "svc-user"),
				"password":    tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newScpConnectionRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newScpConnectionRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["password"] = tftypes.NewValue(tftypes.String, tc.configPass)
			configOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newScpConnectionRawValue(ctx, schemaResp, configOverrides)

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

			want := fmt.Sprintf(`"password":%q`, tc.configPass)
			got := strings.Contains(capturedPatchBody, want)
			if got != tc.expectInBody {
				t.Errorf("expected password present in PATCH body = %v, got %v (body: %s)", tc.expectInBody, got, capturedPatchBody)
			}

			var final CMScpConnectionTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.Password.IsNull() {
				t.Errorf("expected password to be null in state (write-only), got %q", final.Password.ValueString())
			}
		})
	}
}
