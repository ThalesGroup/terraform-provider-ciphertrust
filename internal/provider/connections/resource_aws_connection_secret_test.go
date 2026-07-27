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

// Test_AWSConnectionSchema_SecretAccessKeyWriteOnly verifies that
// ciphertrust_aws_connection.secret_access_key is marked WriteOnly (never stored in
// state/plan artifacts, per the AWS connection SecScan finding) and that
// secret_access_key_version exists as the companion state-tracked rotation trigger.
// access_key_id must remain unaffected: it is not a true secret (CM echoes it back on
// GET), so it keeps its existing Computed-based drift detection instead of going
// write-only.
func Test_AWSConnectionSchema_SecretAccessKeyWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCCKMAWSConnection{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	secretAttr, ok := resp.Schema.Attributes["secret_access_key"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected secret_access_key attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["secret_access_key"])
	}
	if !secretAttr.WriteOnly {
		t.Error("expected secret_access_key schema attribute to be marked WriteOnly: true")
	}
	if !secretAttr.Sensitive {
		t.Error("expected secret_access_key schema attribute to remain marked Sensitive: true")
	}
	if secretAttr.Computed {
		t.Error("expected secret_access_key schema attribute to no longer be Computed (WriteOnly attributes cannot be Computed)")
	}

	if _, ok := resp.Schema.Attributes["secret_access_key_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected secret_access_key_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["secret_access_key_version"])
	}

	accessKeyAttr, ok := resp.Schema.Attributes["access_key_id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected access_key_id attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["access_key_id"])
	}
	if accessKeyAttr.WriteOnly {
		t.Error("access_key_id must not be WriteOnly: it is not a true secret (CM echoes it back on GET) and relies on Computed-based drift detection")
	}
	if !accessKeyAttr.Computed {
		t.Error("access_key_id must remain Computed for its existing drift-detection behavior")
	}
}

// newAWSConnectionRawValue builds a tftypes.Value covering every attribute declared in
// resourceCCKMAWSConnection's Schema(), defaulting every attribute to null and applying
// the given overrides. Attribute types (including the nested iam_role_anywhere object,
// and the labels/meta/products collection types) are derived from the schema itself, so
// this helper does not need to hand-duplicate the nested type shapes.
func newAWSConnectionRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_AWSConnectionCreate_SecretAccessKeyReadFromConfigNotPlan proves that Create()
// reads secret_access_key from req.Config rather than req.Plan. This matters because the
// framework nulls WriteOnly attributes out of the plan before Create() ever runs; reading
// from plan (the pre-fix behavior) would silently send an empty secret to CM instead of
// the value the user configured.
func Test_AWSConnectionCreate_SecretAccessKeyReadFromConfigNotPlan(t *testing.T) {
	const wantSecret = "shhh-its-a-secret"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"conn-id-1","uri":"u","account":"a","devAccount":"d","application":"app","createdAt":"c","updatedAt":"u","category":"cat","service":"svc","resource_url":"ru"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCCKMAWSConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":             tftypes.NewValue(tftypes.String, "my-conn"),
		"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
	}

	// Plan: secret_access_key is null, exactly as the framework leaves it for a
	// WriteOnly attribute before Create() runs.
	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["secret_access_key"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

	// Config: secret_access_key carries the actual HCL-configured value.
	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["secret_access_key"] = tftypes.NewValue(tftypes.String, wantSecret)
	configValue := newAWSConnectionRawValue(ctx, schemaResp, configOverrides)

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

	if want := fmt.Sprintf(`"secret_access_key":%q`, wantSecret); !strings.Contains(capturedBody, want) {
		t.Errorf("expected request payload to contain %s (read from config), got body: %s", want, capturedBody)
	}

	var final AWSConnectionModelTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.SecretAccessKey.IsNull() {
		t.Errorf("expected secret_access_key to be null in state (write-only), got %q", final.SecretAccessKey.ValueString())
	}
}

// Test_AWSConnectionUpdate_SecretAccessKeyVersionGatesResend proves that Update() only
// re-sends secret_access_key to CM when secret_access_key_version changes between state
// and plan. Since secret_access_key is write-only (never stored in state), it cannot be
// diffed on its own — secret_access_key_version is the explicit signal that the caller
// wants the current value re-sent. Without this gate, secret_access_key would either
// never be resendable, or (the pre-fix bug) get silently restored from empty prior state.
func Test_AWSConnectionUpdate_SecretAccessKeyVersionGatesResend(t *testing.T) {
	const connID = "conn-id-1"

	tests := []struct {
		name         string
		stateVersion int64
		planVersion  int64
		configSecret string
		expectInBody bool
	}{
		{
			name:         "version unchanged: secret omitted from payload",
			stateVersion: 1,
			planVersion:  1,
			configSecret: "unused-secret",
			expectInBody: false,
		},
		{
			name:         "version bumped: secret included from config",
			stateVersion: 1,
			planVersion:  2,
			configSecret: "rotated-secret",
			expectInBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedPatchBody string
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPatch:
					body, _ := io.ReadAll(r.Body)
					capturedPatchBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"id":%q}`, connID)
				case http.MethodGet:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"id":%q}`, connID)
				default:
					t.Fatalf("unexpected method %s", r.Method)
				}
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := &common.Client{
				CipherTrustURL: server.URL,
				HTTPClient:     server.Client(),
				Log:            hclog.NewNullLogger(),
			}

			r := &resourceCCKMAWSConnection{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":                tftypes.NewValue(tftypes.String, connID),
				"name":              tftypes.NewValue(tftypes.String, "my-conn"),
				"is_role_anywhere":  tftypes.NewValue(tftypes.Bool, false),
				"secret_access_key": tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["secret_access_key_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newAWSConnectionRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["secret_access_key_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["secret_access_key"] = tftypes.NewValue(tftypes.String, tc.configSecret)
			configOverrides["secret_access_key_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newAWSConnectionRawValue(ctx, schemaResp, configOverrides)

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

			want := fmt.Sprintf(`"secret_access_key":%q`, tc.configSecret)
			got := strings.Contains(capturedPatchBody, want)
			if got != tc.expectInBody {
				t.Errorf("expected secret_access_key present in PATCH body = %v, got %v (body: %s)", tc.expectInBody, got, capturedPatchBody)
			}

			var final AWSConnectionModelTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.SecretAccessKey.IsNull() {
				t.Errorf("expected secret_access_key to be null in state (write-only), got %q", final.SecretAccessKey.ValueString())
			}
		})
	}
}
