package cm

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

// Test_CMInterfaceSchema_RegistrationTokenAndCertificatePasswordWriteOnly verifies that
// registration_token and the nested certificate.password are marked WriteOnly (never
// stored in state/plan artifacts) and that their companion *_version attributes exist as
// the state-tracked rotation trigger.
func Test_CMInterfaceSchema_RegistrationTokenAndCertificatePasswordWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCMInterface{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	regTokenAttr, ok := resp.Schema.Attributes["registration_token"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected registration_token attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["registration_token"])
	}
	if !regTokenAttr.WriteOnly {
		t.Error("expected registration_token schema attribute to be marked WriteOnly: true")
	}
	if !regTokenAttr.Sensitive {
		t.Error("expected registration_token schema attribute to remain marked Sensitive: true")
	}
	if _, ok := resp.Schema.Attributes["registration_token_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected registration_token_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["registration_token_version"])
	}

	certAttr, ok := resp.Schema.Attributes["certificate"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("expected certificate to be schema.SingleNestedAttribute, got %T", resp.Schema.Attributes["certificate"])
	}
	pwAttr, ok := certAttr.Attributes["password"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected certificate.password to be schema.StringAttribute, got %T", certAttr.Attributes["password"])
	}
	if !pwAttr.WriteOnly {
		t.Error("expected certificate.password to be marked WriteOnly: true")
	}
	if !pwAttr.Sensitive {
		t.Error("expected certificate.password to remain marked Sensitive: true")
	}
	if _, ok := certAttr.Attributes["password_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected certificate.password_version to be schema.Int64Attribute, got %T", certAttr.Attributes["password_version"])
	}
}

// newInterfaceRawValue builds a tftypes.Value covering every attribute declared in
// resourceCMInterface's Schema(), defaulting every attribute to null and applying the
// given overrides.
func newInterfaceRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_CMInterfaceCreate_RegistrationTokenReadFromConfigNotPlan proves that Create() reads
// registration_token from req.Config rather than req.Plan. This matters because the
// framework nulls WriteOnly attributes out of the plan before Create() ever runs; reading
// from plan (the pre-fix behavior) would silently send an empty token to CM instead of the
// value the user configured.
func Test_CMInterfaceCreate_RegistrationTokenReadFromConfigNotPlan(t *testing.T) {
	const wantToken = "shhh-its-a-token"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_INTERFACE, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"iface-1","port":9000,"createdAt":"c","updatedAt":"u"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMInterface{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"port":              tftypes.NewValue(tftypes.Number, int64(9000)),
		"interface_type":    tftypes.NewValue(tftypes.String, "nae"),
		"auto_registration": tftypes.NewValue(tftypes.Bool, true),
	}

	// Plan: registration_token is null, exactly as the framework leaves it for a
	// WriteOnly attribute before Create() runs.
	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["registration_token"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newInterfaceRawValue(ctx, schemaResp, planOverrides)

	// Config: registration_token carries the actual HCL-configured value.
	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["registration_token"] = tftypes.NewValue(tftypes.String, wantToken)
	configValue := newInterfaceRawValue(ctx, schemaResp, configOverrides)

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

	if want := fmt.Sprintf(`"registration_token":%q`, wantToken); !strings.Contains(capturedBody, want) {
		t.Errorf("expected request payload to contain %s (read from config), got body: %s", want, capturedBody)
	}

	var final CMInterfaceTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.RegToken.IsNull() {
		t.Errorf("expected registration_token to be null in state (write-only), got %q", final.RegToken.ValueString())
	}
}

// Test_CMInterfaceUpdate_RegistrationTokenVersionGatesResend proves that Update() only
// re-sends registration_token to CM when registration_token_version changes between state
// and plan. Since registration_token is write-only (never stored in state), it cannot be
// diffed on its own — registration_token_version is the explicit signal that the caller
// wants the current value re-sent (or cleared, if empty).
func Test_CMInterfaceUpdate_RegistrationTokenVersionGatesResend(t *testing.T) {
	const ifaceName = "nae"

	tests := []struct {
		name               string
		stateVersion       int64
		planVersion        int64
		configToken        string
		expectFieldInPatch bool
	}{
		{
			name:               "version unchanged: registration_token omitted from payload",
			stateVersion:       1,
			planVersion:        1,
			configToken:        "unused-token",
			expectFieldInPatch: false,
		},
		{
			name:               "version bumped: registration_token included from config",
			stateVersion:       1,
			planVersion:        2,
			configToken:        "rotated-token",
			expectFieldInPatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedPatchBody string
			mux := http.NewServeMux()
			mux.HandleFunc("/"+common.URL_INTERFACE+"/"+ifaceName, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPatch:
					body, _ := io.ReadAll(r.Body)
					capturedPatchBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"updatedAt":"u2"}`)
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

			r := &resourceCMInterface{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":                 tftypes.NewValue(tftypes.String, "iface-1"),
				"port":               tftypes.NewValue(tftypes.Number, int64(9000)),
				"name":               tftypes.NewValue(tftypes.String, ifaceName),
				"interface_type":     tftypes.NewValue(tftypes.String, "nae"),
				"created_at":         tftypes.NewValue(tftypes.String, "c"),
				"registration_token": tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["registration_token_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newInterfaceRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["registration_token_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newInterfaceRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["registration_token"] = tftypes.NewValue(tftypes.String, tc.configToken)
			configOverrides["registration_token_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newInterfaceRawValue(ctx, schemaResp, configOverrides)

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

			want := fmt.Sprintf(`"registration_token":%q`, tc.configToken)
			got := strings.Contains(capturedPatchBody, want)
			if got != tc.expectFieldInPatch {
				t.Errorf("expected registration_token present in PATCH body = %v, got %v (body: %s)", tc.expectFieldInPatch, got, capturedPatchBody)
			}

			var final CMInterfaceTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.RegToken.IsNull() {
				t.Errorf("expected registration_token to be null in state (write-only), got %q", final.RegToken.ValueString())
			}
		})
	}
}
