package cte

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

// Test_CteClientGroupSchema_PasswordWriteOnly verifies that
// ciphertrust_cte_client_group.password is marked WriteOnly (never stored in
// state/plan artifacts, per the SecScan write-only hardening pass) and that
// password_version exists as the companion state-tracked rotation trigger.
func Test_CteClientGroupSchema_PasswordWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCTEClientGroup{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

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

	if _, ok := resp.Schema.Attributes["password_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected password_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["password_version"])
	}
}

// newCteClientGroupRawValue builds a tftypes.Value covering every attribute declared in
// resourceCTEClientGroup's Schema(), defaulting every attribute to null and applying the
// given overrides. Attribute types are derived from the schema itself.
func newCteClientGroupRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_CteClientGroupCreate_PasswordReadFromConfigNotPlan proves that Create() reads
// password from req.Config rather than req.Plan, since the framework nulls WriteOnly
// attributes out of the plan before Create() ever runs.
func Test_CteClientGroupCreate_PasswordReadFromConfigNotPlan(t *testing.T) {
	const wantPassword = "cte-cg-secret"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/transparent-encryption/clientgroups", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"cte-cg-id-1"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCTEClientGroup{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":                     tftypes.NewValue(tftypes.String, "my-cte-cg"),
		"cluster_type":             tftypes.NewValue(tftypes.String, "NON-CLUSTER"),
		"password_creation_method": tftypes.NewValue(tftypes.String, "MANUAL"),
	}

	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["password"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newCteClientGroupRawValue(ctx, schemaResp, planOverrides)

	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["password"] = tftypes.NewValue(tftypes.String, wantPassword)
	configValue := newCteClientGroupRawValue(ctx, schemaResp, configOverrides)

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

	var final CTEClientGroupTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.Password.IsNull() {
		t.Errorf("expected password to be null in state (write-only), got %q", final.Password.ValueString())
	}
}

// cteClientGroupBaseOverrides returns the attribute overrides shared by plan and state in
// the Update() tests below: everything equal so that only password_version differs,
// isolating the specific guard/branch under test.
func cteClientGroupBaseOverrides(id, opType string) map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, id),
		"name":         tftypes.NewValue(tftypes.String, "my-cte-cg"),
		"cluster_type": tftypes.NewValue(tftypes.String, "NON-CLUSTER"),
		"op_type":      tftypes.NewValue(tftypes.String, opType),
		"password":     tftypes.NewValue(tftypes.String, nil),
		"client_list":  tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{}),
	}
}

// Test_CteClientGroupUpdate_UpdateOpType_PasswordVersionGatesResend proves that Update()
// with op_type "update" only re-sends password to CM when password_version changes
// between state and plan.
func Test_CteClientGroupUpdate_UpdateOpType_PasswordVersionGatesResend(t *testing.T) {
	const groupID = "cte-cg-id-1"

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
			mux.HandleFunc("/api/v1/transparent-encryption/clientgroups/"+groupID, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPatch {
					t.Fatalf("unexpected method %s", r.Method)
				}
				body, _ := io.ReadAll(r.Body)
				capturedPatchBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id":%q}`, groupID)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := &common.Client{
				CipherTrustURL: server.URL,
				HTTPClient:     server.Client(),
				Log:            hclog.NewNullLogger(),
			}

			r := &resourceCTEClientGroup{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			base := cteClientGroupBaseOverrides(groupID, "update")

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				stateOverrides[k] = v
			}
			stateOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newCteClientGroupRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				planOverrides[k] = v
			}
			planOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newCteClientGroupRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				configOverrides[k] = v
			}
			configOverrides["password"] = tftypes.NewValue(tftypes.String, tc.configPass)
			configOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newCteClientGroupRawValue(ctx, schemaResp, configOverrides)

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

			var final CTEClientGroupTFSDK
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

// Test_CteClientGroupUpdate_UpdatePasswordOpType_VersionGatesResend proves that Update()
// with op_type "update-password" only calls the dedicated password-rotation sub-endpoint
// payload with the current password when password_version changes between state and
// plan.
func Test_CteClientGroupUpdate_UpdatePasswordOpType_VersionGatesResend(t *testing.T) {
	const groupID = "cte-cg-id-1"

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
			mux.HandleFunc("/api/v1/transparent-encryption/clientgroups/"+groupID+"/password", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPatch {
					t.Fatalf("unexpected method %s", r.Method)
				}
				body, _ := io.ReadAll(r.Body)
				capturedPatchBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id":%q}`, groupID)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := &common.Client{
				CipherTrustURL: server.URL,
				HTTPClient:     server.Client(),
				Log:            hclog.NewNullLogger(),
			}

			r := &resourceCTEClientGroup{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			base := cteClientGroupBaseOverrides(groupID, "update-password")

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				stateOverrides[k] = v
			}
			stateOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newCteClientGroupRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				planOverrides[k] = v
			}
			planOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newCteClientGroupRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				configOverrides[k] = v
			}
			configOverrides["password"] = tftypes.NewValue(tftypes.String, tc.configPass)
			configOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newCteClientGroupRawValue(ctx, schemaResp, configOverrides)

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

			var final CTEClientGroupTFSDK
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

// Test_CteClientGroupUpdate_RejectsPasswordVersionBumpUnderOtherOpTypes proves that
// bumping password_version while using an op_type that doesn't accept password changes
// (auth-binaries, reset-password, remove-client, add-client) is rejected. Before the
// WriteOnly conversion this was enforced by directly comparing plan.Password to
// state.Password; since both are now always null, password_version is the only signal
// left that a password change was attempted.
func Test_CteClientGroupUpdate_RejectsPasswordVersionBumpUnderOtherOpTypes(t *testing.T) {
	opTypes := []string{"auth-binaries", "reset-password", "remove-client", "add-client"}

	for _, opType := range opTypes {
		t.Run(opType, func(t *testing.T) {
			// No HTTP server needed: the version-bump guard fires and returns before
			// any network call in each of these branches.
			r := &resourceCTEClientGroup{client: &common.Client{Log: hclog.NewNullLogger()}}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			base := cteClientGroupBaseOverrides("cte-cg-id-1", opType)

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				stateOverrides[k] = v
			}
			stateOverrides["password_version"] = tftypes.NewValue(tftypes.Number, 1)
			stateValue := newCteClientGroupRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				planOverrides[k] = v
			}
			planOverrides["password_version"] = tftypes.NewValue(tftypes.Number, 2)
			planValue := newCteClientGroupRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range base {
				configOverrides[k] = v
			}
			configOverrides["password"] = tftypes.NewValue(tftypes.String, "attempted-rotation")
			configOverrides["password_version"] = tftypes.NewValue(tftypes.Number, 2)
			configValue := newCteClientGroupRawValue(ctx, schemaResp, configOverrides)

			req := resource.UpdateRequest{
				Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
				Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
				State:  tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
			}
			resp := &resource.UpdateResponse{
				State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
			}

			r.Update(ctx, req, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatalf("expected Update() to reject a password_version bump under op_type %q, got no diagnostics", opType)
			}
			found := false
			for _, d := range resp.Diagnostics {
				if strings.Contains(d.Detail(), "password") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected a diagnostic mentioning password rejection under op_type %q, got: %v", opType, resp.Diagnostics)
			}
		})
	}
}
