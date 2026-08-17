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

// Test_InterfaceCertificateRenewalSchema_PasswordWriteOnly verifies that password is
// marked WriteOnly (never stored in state/plan artifacts) and carries no RequiresReplace
// plan modifier of its own — trigger is the sole, documented signal that controls when a
// renewal (and re-send of password) happens.
func Test_InterfaceCertificateRenewalSchema_PasswordWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceInterfaceCertificateRenewal{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

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
	if len(passwordAttr.PlanModifiers) != 0 {
		t.Error("expected password to carry no plan modifiers: a RequiresReplace on a write-only attribute " +
			"would compare the real config value against an always-null state value and misfire on every plan")
	}
}

// newInterfaceCertRenewalRawValue builds a tftypes.Value covering every attribute declared
// in resourceInterfaceCertificateRenewal's Schema(), defaulting every attribute to null and
// applying the given overrides.
func newInterfaceCertRenewalRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_InterfaceCertificateRenewalCreate_PasswordReadFromConfigNotPlan proves that
// Create() reads password from req.Config rather than req.Plan. This matters because the
// framework nulls WriteOnly attributes out of the plan before Create() ever runs; reading
// from plan (the pre-fix behavior) would silently send an empty password to CM instead of
// the value the user configured.
func Test_InterfaceCertificateRenewalCreate_PasswordReadFromConfigNotPlan(t *testing.T) {
	const wantPassword = "shhh-its-a-secret"
	const interfaceName = "web"

	var capturedStageBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_INTERFACE+"/"+interfaceName, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"name":"web"}`)
	})
	mux.HandleFunc("/"+common.URL_INTERFACE+"/"+interfaceName+"/renewal-certificate", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedStageBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"certificates":"-----BEGIN CERTIFICATE-----\nMIIBfoo\n-----END CERTIFICATE-----"}`)
	})
	mux.HandleFunc("/"+common.URL_INTERFACE+"/"+interfaceName+"/renewal-certificate/apply", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceInterfaceCertificateRenewal{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"interface_name":  tftypes.NewValue(tftypes.String, interfaceName),
		"format":          tftypes.NewValue(tftypes.String, "PKCS12"),
		"certificate":     tftypes.NewValue(tftypes.String, "cert-data"),
		"trigger":         tftypes.NewValue(tftypes.String, "1"),
		"generate":        tftypes.NewValue(tftypes.Bool, false),
		"skip_validation": tftypes.NewValue(tftypes.Bool, false),
	}

	// Plan: password is null, exactly as the framework leaves it for a WriteOnly
	// attribute before Create() runs.
	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["password"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newInterfaceCertRenewalRawValue(ctx, schemaResp, planOverrides)

	// Config: password carries the actual HCL-configured value.
	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["password"] = tftypes.NewValue(tftypes.String, wantPassword)
	configValue := newInterfaceCertRenewalRawValue(ctx, schemaResp, configOverrides)

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

	if want := fmt.Sprintf(`"password":%q`, wantPassword); !strings.Contains(capturedStageBody, want) {
		t.Errorf("expected stage request payload to contain %s (read from config), got body: %s", want, capturedStageBody)
	}

	var final InterfaceCertificateRenewalTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.Password.IsNull() {
		t.Errorf("expected password to be null in state (write-only), got %q", final.Password.ValueString())
	}
}
