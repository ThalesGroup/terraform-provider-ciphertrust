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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// newAzureConnectionRawValue builds a tftypes.Value covering every attribute declared in
// resourceAzureConnection's Schema(), defaulting every attribute to null and applying the
// given overrides. Attribute types are derived from the schema itself, so this helper does
// not need to hand-duplicate the collection type shapes (labels/meta/products).
func newAzureConnectionRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_AzureConnectionCreate_ClientSecretReadFromConfigNotPlan proves that Create() reads
// client_secret from req.Config rather than req.Plan. This matters because the framework
// nulls WriteOnly attributes out of the plan before Create() ever runs; reading from plan
// (the pre-fix behavior) would silently send an empty secret to CM instead of the value
// the user configured.
func Test_AzureConnectionCreate_ClientSecretReadFromConfigNotPlan(t *testing.T) {
	const wantSecret = "shhh-its-a-secret"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_AZURE_CONNECTION, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"conn-id-1"}`)
	})
	mux.HandleFunc("/"+common.URL_AZURE_CONNECTION+"/conn-id-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"conn-id-1"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceAzureConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":      tftypes.NewValue(tftypes.String, "my-azure-conn"),
		"client_id": tftypes.NewValue(tftypes.String, "client-id"),
		"tenant_id": tftypes.NewValue(tftypes.String, "tenant-id"),
	}

	// Plan: client_secret is null, exactly as the framework leaves it for a WriteOnly
	// attribute before Create() runs.
	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["client_secret"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newAzureConnectionRawValue(ctx, schemaResp, planOverrides)

	// Config: client_secret carries the actual HCL-configured value.
	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["client_secret"] = tftypes.NewValue(tftypes.String, wantSecret)
	configValue := newAzureConnectionRawValue(ctx, schemaResp, configOverrides)

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

	if want := fmt.Sprintf(`"client_secret":%q`, wantSecret); !strings.Contains(capturedBody, want) {
		t.Errorf("expected request payload to contain %s (read from config), got body: %s", want, capturedBody)
	}

	var final AzureConnectionTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.ClientSecret.IsNull() {
		t.Errorf("expected client_secret to be null in state (write-only), got %q", final.ClientSecret.ValueString())
	}
}

// Test_AzureConnectionUpdate_ClientSecretVersionGatesResend proves that Update() only
// re-sends client_secret to CM when client_secret_version changes between state and plan.
// Since client_secret is write-only (never stored in state), it cannot be diffed on its
// own — client_secret_version is the explicit signal that the caller wants the current
// value re-sent.
func Test_AzureConnectionUpdate_ClientSecretVersionGatesResend(t *testing.T) {
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
			mux.HandleFunc("/"+common.URL_AZURE_CONNECTION+"/"+connID, func(w http.ResponseWriter, r *http.Request) {
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

			r := &resourceAzureConnection{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":            tftypes.NewValue(tftypes.String, connID),
				"name":          tftypes.NewValue(tftypes.String, "my-azure-conn"),
				"client_id":     tftypes.NewValue(tftypes.String, "client-id"),
				"tenant_id":     tftypes.NewValue(tftypes.String, "tenant-id"),
				"client_secret": tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["client_secret_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newAzureConnectionRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["client_secret_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newAzureConnectionRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["client_secret"] = tftypes.NewValue(tftypes.String, tc.configSecret)
			configOverrides["client_secret_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newAzureConnectionRawValue(ctx, schemaResp, configOverrides)

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

			want := fmt.Sprintf(`"client_secret":%q`, tc.configSecret)
			got := strings.Contains(capturedPatchBody, want)
			if got != tc.expectInBody {
				t.Errorf("expected client_secret present in PATCH body = %v, got %v (body: %s)", tc.expectInBody, got, capturedPatchBody)
			}

			var final AzureConnectionTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.ClientSecret.IsNull() {
				t.Errorf("expected client_secret to be null in state (write-only), got %q", final.ClientSecret.ValueString())
			}
		})
	}
}

// Test_AzureConnectionUpdate_ClearingSecretViaVersionBumpIsBlocked proves that Update()
// rejects a version bump with no accompanying client_secret value in config — CM does not
// support clearing client_secret, so this must fail rather than silently leaving state and
// CM's live value out of sync.
func Test_AzureConnectionUpdate_ClearingSecretViaVersionBumpIsBlocked(t *testing.T) {
	const connID = "conn-id-1"

	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_AZURE_CONNECTION+"/"+connID, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("expected no HTTP calls when clearing is blocked, got %s %s", r.Method, r.URL.Path)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceAzureConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	baseOverrides := map[string]tftypes.Value{
		"id":            tftypes.NewValue(tftypes.String, connID),
		"name":          tftypes.NewValue(tftypes.String, "my-azure-conn"),
		"client_id":     tftypes.NewValue(tftypes.String, "client-id"),
		"tenant_id":     tftypes.NewValue(tftypes.String, "tenant-id"),
		"client_secret": tftypes.NewValue(tftypes.String, nil),
	}

	stateOverrides := map[string]tftypes.Value{}
	for k, v := range baseOverrides {
		stateOverrides[k] = v
	}
	stateOverrides["client_secret_version"] = tftypes.NewValue(tftypes.Number, int64(1))
	stateValue := newAzureConnectionRawValue(ctx, schemaResp, stateOverrides)

	planOverrides := map[string]tftypes.Value{}
	for k, v := range baseOverrides {
		planOverrides[k] = v
	}
	planOverrides["client_secret_version"] = tftypes.NewValue(tftypes.Number, int64(2))
	planValue := newAzureConnectionRawValue(ctx, schemaResp, planOverrides)

	// Config bumps the version but supplies no client_secret value — an attempted clear.
	configValue := newAzureConnectionRawValue(ctx, schemaResp, planOverrides)

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
		t.Fatal("expected Update() to reject clearing client_secret via a version bump with no value, got no diagnostics")
	}
}
