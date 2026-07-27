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

// Test_CteClientSchema_PasswordWriteOnly verifies that ciphertrust_cte_client.password
// is marked WriteOnly (never stored in state/plan artifacts, per the SecScan write-only
// hardening pass) and that password_version exists as the companion state-tracked
// rotation trigger.
func Test_CteClientSchema_PasswordWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCTEClient{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

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

// newCteClientRawValue builds a tftypes.Value covering every attribute declared in
// resourceCTEClient's Schema(), defaulting every attribute to null and applying the
// given overrides. Attribute types are derived from the schema itself.
func newCteClientRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_CteClientCreate_PasswordReadFromConfigNotPlan proves that Create() reads
// password from req.Config rather than req.Plan, since the framework nulls WriteOnly
// attributes out of the plan before Create() ever runs.
func Test_CteClientCreate_PasswordReadFromConfigNotPlan(t *testing.T) {
	const wantPassword = "cte-client-secret"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/transparent-encryption/clients", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"cte-client-id-1","profile_id":"prof-1","profile_name":"default"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCTEClient{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":                     tftypes.NewValue(tftypes.String, "my-cte-client"),
		"client_type":              tftypes.NewValue(tftypes.String, "FS"),
		"password_creation_method": tftypes.NewValue(tftypes.String, "MANUAL"),
	}

	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["password"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newCteClientRawValue(ctx, schemaResp, planOverrides)

	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["password"] = tftypes.NewValue(tftypes.String, wantPassword)
	configValue := newCteClientRawValue(ctx, schemaResp, configOverrides)

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

	var final CTEClientTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.Password.IsNull() {
		t.Errorf("expected password to be null in state (write-only), got %q", final.Password.ValueString())
	}
}

// Test_CteClientCreate_NullConfigPasswordNeverSentAsLiteralNullString is a regression
// test for a real bug caught live against CipherTrust Manager: types.String.String()
// returns the literal text "<null>" (not "") when the value is null, so a guard written
// as TrimString(config.Password.String()) != "" treats an unconfigured (null) password
// as non-empty and sends the literal string "<null>" to CM. The fix uses
// config.Password.ValueString() directly, which correctly returns "" for null.
func Test_CteClientCreate_NullConfigPasswordNeverSentAsLiteralNullString(t *testing.T) {
	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/transparent-encryption/clients", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"cte-client-id-1","profile_id":"prof-1","profile_name":"default"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCTEClient{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	// password_creation_method=GENERATE, password left completely unconfigured (null).
	overrides := map[string]tftypes.Value{
		"name":                     tftypes.NewValue(tftypes.String, "my-cte-client"),
		"client_type":              tftypes.NewValue(tftypes.String, "FS"),
		"password_creation_method": tftypes.NewValue(tftypes.String, "GENERATE"),
		"password":                 tftypes.NewValue(tftypes.String, nil),
	}
	planValue := newCteClientRawValue(ctx, schemaResp, overrides)
	configValue := newCteClientRawValue(ctx, schemaResp, overrides)

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

	if strings.Contains(capturedBody, "<null>") {
		t.Errorf("regression: request payload contains the literal string \"<null>\" instead of omitting the field: %s", capturedBody)
	}
}

// Test_CteClientUpdate_PasswordVersionGatesResend proves that Update() only re-sends
// password to CM when password_version changes between state and plan. Since password
// is write-only (never stored in state), it cannot be diffed on its own —
// password_version is the explicit signal that the caller wants the current value
// re-sent.
func Test_CteClientUpdate_PasswordVersionGatesResend(t *testing.T) {
	const clientID = "cte-client-id-1"

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
			mux.HandleFunc("/api/v1/transparent-encryption/clients/"+clientID, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPatch {
					t.Fatalf("unexpected method %s", r.Method)
				}
				body, _ := io.ReadAll(r.Body)
				capturedPatchBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id":%q,"profile_id":"prof-1","profile_name":"default"}`, clientID)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := &common.Client{
				CipherTrustURL: server.URL,
				HTTPClient:     server.Client(),
				Log:            hclog.NewNullLogger(),
			}

			r := &resourceCTEClient{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":                       tftypes.NewValue(tftypes.String, clientID),
				"name":                     tftypes.NewValue(tftypes.String, "my-cte-client"),
				"client_type":              tftypes.NewValue(tftypes.String, "FS"),
				"password_creation_method": tftypes.NewValue(tftypes.String, "MANUAL"),
				"password":                 tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newCteClientRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newCteClientRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["password"] = tftypes.NewValue(tftypes.String, tc.configPass)
			configOverrides["password_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newCteClientRawValue(ctx, schemaResp, configOverrides)

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

			var final CTEClientTFSDK
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
